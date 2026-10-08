/// Manual pairing: the fallback that needs neither mDNS nor Bluetooth.
///
/// # Why this tier exists
///
/// Every earlier tier assumes *something* about the environment: the LAN tier
/// assumes multicast works, the hotspot tier assumes Android can host, the BLE
/// tier assumes the radio is usable and the ROM allows advertising. Vendor ROMs
/// (MIUI/HyperOS, ColorOS, vivo) ship their own per-app LAN and Bluetooth
/// switches that ignore Android permissions entirely, and client-isolated Wi-Fi
/// kills multicast outright. When all of those are true at once, the only
/// channel left is a human reading a short string off one screen and entering it
/// on the other.
///
/// So this is deliberately the dumbest possible transport: a compact text
/// payload the user copies (or scans) from the hosting device, which yields a
/// [`PeerAddress`] to dial directly. Discovery is bypassed entirely; the
/// connection then behaves exactly like any other, including the six-digit SAS.
///
/// # Why a URI and not just `host:port`
///
/// The payload also has to carry *which identity* to expect, so the receiving
/// side can warn about a changed key before the user compares a code. A plain
/// `192.168.1.5:44353` cannot. The `aero://` scheme also makes the payload
/// recognisable as Aero's (so a paste of the wrong string fails clearly) and
/// leaves room to add fields without breaking older peers.
///
/// # Trust model
///
/// Typed or pasted input is **untrusted**, exactly like an mDNS TXT record or a
/// BLE advertisement. Every field is validated: the address must be a dialable
/// IP literal (no hostname, no loopback), the port must be in range, and the
/// fingerprint is only ever *displayed* as a hint. Nothing here authenticates
/// the peer - the SAS over the resulting TLS link still does that, and a manual
/// payload pointing at an attacker is defeated by the code mismatch the user
/// sees.
library;

import 'dart:convert';
import 'dart:io';

import '../logging.dart';
import '../models.dart';

/// Scheme for the shareable payload. `aero://` so a wrong paste is obvious.
const String kManualUriScheme = 'aero';

/// Hard cap on a pasted payload. A connection string is tens of characters;
/// anything approaching this is either corrupt or hostile, and must not be fed
/// to a parser.
const int kMaxManualPayloadLength = 512;

/// A parsed manual-connection payload: enough to dial a peer directly.
///
/// Deliberately *not* a [DiscoveredPeer]: it carries no trusted identity and no
/// key. It is a hint - "a device calling itself X can be reached at Y" - and the
/// caller must still run the normal handshake and SAS comparison before anything
/// is believed.
class ManualConnection {
  const ManualConnection({
    required this.host,
    required this.port,
    this.deviceName = '',
    this.deviceId = '',
    this.publicKeyHash = '',
    this.os = '',
  });

  /// Dialable IP literal. Validated at parse time.
  final String host;
  final int port;

  /// Advertised device name, for display. Untrusted; sanitised.
  final String deviceName;

  /// Advertised device id. Untrusted, but the handle for dedup and the
  /// pre-pairing "your key changed" warning.
  final String deviceId;

  /// `PeerInfo.hashPublicKey` value, when the host chose to include it.
  final String publicKeyHash;

  /// Advertised OS name, for the peer row.
  final String os;

  /// The transport address to dial.
  PeerAddress get address => PeerAddress(host: host, port: port);

  /// The `aero://` form, suitable for copying or rendering as a QR code.
  ///
  /// Query parameters are used rather than a path so the payload stays
  /// `aero://connect?host=...&port=...` - readable, order-independent, and
  /// forward-compatible.
  String toUriString() {
    final params = <String, String>{
      'host': host,
      'port': '$port',
      if (deviceName.isNotEmpty) 'name': deviceName,
      if (deviceId.isNotEmpty) 'id': deviceId,
      if (publicKeyHash.isNotEmpty) 'pk': publicKeyHash,
      if (os.isNotEmpty) 'os': os,
    };
    // `Uri` handles percent-encoding, so a device name with spaces or unicode
    // round-trips correctly rather than producing a payload the parser rejects.
    return Uri(
      scheme: kManualUriScheme,
      host: 'connect',
      queryParameters: params,
    ).toString();
  }

  @override
  String toString() => 'ManualConnection($deviceName, $host:$port)';
}

/// Why a manual payload could not be parsed.
enum ManualParseFailure {
  /// Empty input.
  empty('empty'),

  /// No recognisable `aero://` scheme, and not a bare `host:port` either.
  unrecognised('unrecognised'),

  /// Longer than [kMaxManualPayloadLength].
  tooLong('too_long'),

  /// The address is missing, or is not a dialable IP literal.
  badAddress('bad_address'),

  /// The port is missing, non-numeric, or out of range.
  badPort('bad_port');

  const ManualParseFailure(this.id);

  /// Stable identifier for logs and diagnostics.
  final String id;

  @override
  String toString() => id;
}

/// The result of parsing a manual payload: either a connection or a reason.
class ManualParseResult {
  const ManualParseResult.success(this.connection)
      : reason = null,
        detail = '';
  const ManualParseResult.failure(this.reason, this.detail)
      : connection = null;

  final ManualConnection? connection;

  /// Non-null exactly when parsing failed.
  final ManualParseFailure? reason;

  /// Human-readable elaboration for the UI.
  final String detail;

  bool get isSuccess => connection != null;

  /// A sentence for the UI.
  String get message => switch (reason) {
        ManualParseFailure.empty => 'Enter or paste a connection string.',
        ManualParseFailure.tooLong =>
          'That is too long to be an Aero connection string.',
        ManualParseFailure.unrecognised =>
          'That does not look like an Aero connection string.',
        ManualParseFailure.badAddress =>
          'The connection string has no usable address.',
        ManualParseFailure.badPort =>
          'The connection string has no usable port.',
        null => '',
      };
}

/// Parse a pasted or typed connection payload.
///
/// Accepts the full `aero://connect?...` form and a bare `host:port`, because a
/// user reading an address off a screen may well type the short form. Returns a
/// typed failure rather than throwing: this is untrusted input and a parse error
/// is an expected outcome, not an exception.
ManualParseResult parseManualConnection(String raw) {
  final text = raw.trim();
  if (text.isEmpty) {
    return const ManualParseResult.failure(ManualParseFailure.empty, '');
  }
  if (text.length > kMaxManualPayloadLength) {
    return ManualParseResult.failure(
      ManualParseFailure.tooLong,
      '${text.length} characters',
    );
  }

  // Try the structured form first. A `Uri.parse` that throws is normal for
  // arbitrary pasted text, so it falls through to the bare form rather than
  // being an error.
  Uri? uri;
  try {
    uri = Uri.parse(text);
  } on FormatException {
    uri = null;
  }

  if (uri != null && uri.scheme == kManualUriScheme) {
    return _fromUri(uri);
  }

  // Bare `host:port`. Deliberately accepts only this exact shape: a bare
  // hostname would need DNS, which may be the very thing that is broken.
  return _fromBare(text);
}

ManualParseResult _fromUri(Uri uri) {
  String? q(String key) => uri.queryParameters[key];

  // Accept the fields from the query, falling back to a `host:port` in the
  // authority (so a hand-written `aero://192.168.1.5:44353` also works).
  final host = q('host') ?? (uri.host == 'connect' ? '' : uri.host);
  final portText = q('port') ?? (uri.hasPort ? '${uri.port}' : '');

  final hostResult = _validateHost(host);
  if (hostResult != null) return hostResult;

  final portResult = _validatePort(portText);
  if (portResult != null) return portResult;

  return ManualParseResult.success(
    ManualConnection(
      host: host,
      port: int.parse(portText),
      deviceName: sanitizeManualText(q('name') ?? '', 80),
      deviceId: sanitizeManualText(q('id') ?? '', 64),
      publicKeyHash: sanitizeManualText(q('pk') ?? '', 64),
      os: sanitizeManualText(q('os') ?? '', 16),
    ),
  );
}

ManualParseResult _fromBare(String text) {
  // IPv6 literals are bracketed; split on the last colon after the bracket to
  // keep `[fe80::1]:44353` from being mangled.
  final colon = text.lastIndexOf(':');
  if (colon <= 0 || colon == text.length - 1) {
    return const ManualParseResult.failure(
      ManualParseFailure.unrecognised,
      'expected host:port',
    );
  }
  final hostPart = text.substring(0, colon);
  final portPart = text.substring(colon + 1);
  final host = hostPart.startsWith('[') && hostPart.endsWith(']')
      ? hostPart.substring(1, hostPart.length - 1)
      : hostPart;

  final hostResult = _validateHost(host);
  if (hostResult != null) return hostResult;
  final portResult = _validatePort(portPart);
  if (portResult != null) return portResult;

  return ManualParseResult.success(
    ManualConnection(host: host, port: int.parse(portPart)),
  );
}

/// Returns a failure result when [host] is unusable, or null when it is fine.
ManualParseResult? _validateHost(String? host) {
  if (host == null || host.isEmpty) {
    return const ManualParseResult.failure(ManualParseFailure.badAddress, 'missing');
  }
  final address = InternetAddress.tryParse(host);
  if (address == null) {
    return ManualParseResult.failure(
      ManualParseFailure.badAddress,
      '"$host" is not an IP address',
    );
  }
  // Loopback is refused: dialling it would connect this device to itself, and a
  // payload that suggests it is either a mistake or bait.
  if (address.isLoopback) {
    return ManualParseResult.failure(
      ManualParseFailure.badAddress,
      'loopback is not a peer',
    );
  }
  if (address.rawAddress.every((b) => b == 0)) {
    return const ManualParseResult.failure(
      ManualParseFailure.badAddress,
      'the wildcard address is not a peer',
    );
  }
  return null;
}

/// Returns a failure result when [port] is unusable, or null when it is fine.
ManualParseResult? _validatePort(String? port) {
  if (port == null || port.isEmpty) {
    return const ManualParseResult.failure(ManualParseFailure.badPort, 'missing');
  }
  final parsed = int.tryParse(port);
  if (parsed == null || parsed <= 0 || parsed >= 65536) {
    return ManualParseResult.failure(
      ManualParseFailure.badPort,
      '"$port" is not a valid port',
    );
  }
  return null;
}

/// Strip control and bidi characters and cap length on untrusted text.
///
/// Same rigour as the mDNS and BLE layers: this text is rendered in the peer
/// list, and a right-to-left override would let a payload spoof the order of a
/// UI row.
String sanitizeManualText(String raw, int maxRunes) {
  final stripped = raw
      .replaceAll(RegExp(r'[\x00-\x1F\x7F\x80-\x9F]'), '')
      .replaceAll(RegExp('[\u200B-\u200F\u202A-\u202E\u2066-\u2069\u00AD\uFEFF]'), '')
      .replaceAll(RegExp(r'\s+'), ' ')
      .trim();
  if (stripped.isEmpty) return '';
  final runes = stripped.runes.toList();
  if (runes.length <= maxRunes) return stripped;
  return String.fromCharCodes(runes.take(maxRunes));
}

/// Build the payload this device should display for manual entry.
///
/// Returns null when there is nothing usable to advertise (no dialable address
/// and no known port), so the UI can say so instead of showing a broken string.
ManualConnection? buildManualConnection({
  required String? host,
  required int? port,
  required String deviceName,
  required String deviceId,
  required String publicKeyHash,
  required String os,
}) {
  if (host == null || host.isEmpty || port == null || port <= 0) {
    coreLog.fine('cannot build a manual payload without a dialable address and port');
    return null;
  }
  return ManualConnection(
    host: host,
    port: port,
    deviceName: sanitizeManualText(deviceName, 80),
    deviceId: sanitizeManualText(deviceId, 64),
    publicKeyHash: sanitizeManualText(publicKeyHash, 64),
    os: sanitizeManualText(os, 16),
  );
}

/// Encode a payload for a QR code, when one is added later.
///
/// Kept separate so the wire format has exactly one definition: a QR renderer
/// would encode these bytes, and the parser above already accepts exactly this
/// string. No QR dependency is introduced yet - see the README.
String encodeManualPayload(ManualConnection connection) =>
    connection.toUriString();

/// Decode bytes a QR scanner would hand back.
///
/// [bytes] is UTF-8 text; anything undecodable is an [ManualParseFailure].
ManualParseResult decodeManualPayload(List<int> bytes) {
  try {
    return parseManualConnection(utf8.decode(bytes, allowMalformed: false));
  } on FormatException {
    return const ManualParseResult.failure(
      ManualParseFailure.unrecognised,
      'not valid UTF-8',
    );
  }
}
