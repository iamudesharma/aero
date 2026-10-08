/// BLE rendezvous: getting two devices to the point where the *real* protocol
/// can start, when mDNS cannot reach across.
///
/// # What this tier is for
///
/// Sometimes the two devices already share an IP link but mDNS cannot see it:
/// guest Wi-Fi with client isolation blocks unicast but not necessarily the
/// link, a corporate network blocks multicast, or the browser was started before
/// the join completed. Sometimes there is no subnet yet and the hotspot
/// credentials themselves need to reach the other device. BLE solves exactly
/// this: a small, always-available, infrastructure-free channel that carries a
/// handful of bytes saying "here is where to find me".
///
/// # What this tier is NOT
///
/// **It never carries file bytes.** BLE throughput is ~90-156 kbit/s: a 10 MiB
/// photo would take minutes, and the existing TLS/TCP path is three orders of
/// magnitude faster. Using BLE for data would be a design failure, not a
/// feature. Every byte that matters travels over the transport that already
/// works.
///
/// # Trust model - read this before changing anything
///
/// A BLE advertisement is **unauthenticated broadcast**, exactly like an mDNS TXT
/// record. Anyone in radio range can advertise any device id, name, or endpoint.
/// So the payload below is treated as hostile input:
///   * every field is length-capped and control characters are stripped;
///   * the endpoint is validated as a dialable address before it is ever used;
///   * **nothing here authenticates the peer.** The payload only gets bytes to
///     the door. The six-digit SAS, derived from the two TLS certificate
///     fingerprints, is still what proves identity - and it still fails against
///     a man in the middle even if that attacker controls the BLE channel
///     entirely and lied about the endpoint. A rendezvous that points at an
///     attacker is defeated by the SAS mismatch the user sees.
library;

import 'dart:io';

import '../logging.dart';

/// The BLE service UUID Aero advertises. A random, Aero-specific 128-bit UUID
/// rather than a 16-bit one: 16-bit UUIDs are reserved for standards bodies, and
/// squatting one would both be incorrect and collide with real devices.
///
/// **This must match the constants on both platform sides.** A central scans for
/// it, a peripheral advertises it; a typo on one side produces a scan that finds
/// nothing with no error anywhere.
const String kAeroBleServiceUuid = 'a1e0b1e5-1c0d-4f2e-9a3b-6d7c8e9f0a1b';

/// How long a rendezvous advertisement stays valid. Matches the SAS lifetime so
/// the two never disagree about whether an attempt is still live.
const Duration kBleRendezvousLifetime = Duration(seconds: 120);

/// Hard cap on the encoded payload. BLE advertisement payloads are tiny (a
/// legacy advertisement is 31 bytes total, shared with flags and the service
/// UUID), so the *advertised* form is an 8-byte rendezvous id only; the rest
/// travels over a GATT read once connected. This cap bounds what a hostile peer
/// can make us buffer.
const int kMaxRendezvousBytes = 512;

/// Why BLE rendezvous is unavailable or failed.
///
/// Typed for the same reason [HotspotFailure] is: "Bluetooth is off" (the user
/// can fix it), "permission denied" (the user can fix it), and "this platform
/// cannot advertise" (they cannot) need different UI.
enum BleFailure {
  /// This platform has no BLE implementation wired up.
  unsupported('unsupported'),

  /// Bluetooth is turned off. User-fixable and worth saying plainly.
  bluetoothOff('bluetooth_off'),

  /// A runtime permission (Android `BLUETOOTH_ADVERTISE`/`CONNECT`, or macOS
  /// Bluetooth TCC) was denied.
  permissionDenied('permission_denied'),

  /// The platform channel is not reachable (unit-test VM, unimplemented).
  channelUnavailable('channel_unavailable'),

  /// Advertising is not supported by this device's controller or ROM. Common on
  /// some Android builds even when Bluetooth itself works.
  advertiseUnsupported('advertise_unsupported'),

  /// Scanning is not available (macOS denied, or the radio is busy).
  scanUnavailable('scan_unavailable'),

  /// Timed out with no peer found.
  timeout('timeout'),

  /// The OS reported a generic failure.
  generic('generic');

  const BleFailure(this.id);

  /// Stable identifier for the wire and for logs.
  final String id;

  static BleFailure fromName(String? name) {
    for (final f in BleFailure.values) {
      if (f.id == name) return f;
    }
    return BleFailure.generic;
  }

  @override
  String toString() => id;
}

/// A BLE-specific inability to rendezvous, carrying a typed reason.
class BleException implements Exception {
  BleException(this.failure, [this.message = '', this.cause]);

  final BleFailure failure;
  final String message;
  final Object? cause;

  @override
  String toString() =>
      'BleException(${failure.id}${message.isEmpty ? '' : ': $message'})';
}

/// The small, untrusted handoff a BLE peer publishes.
///
/// Deliberately **not** a `DiscoveredPeer`: it carries no identity claim we
/// trust and no key. It is a hint - "a device calling itself X can be found at
/// Y" - and the caller must still run the normal `GET /v1/info` handshake and
/// the SAS comparison over the resulting IP link before anything is believed.
class BleRendezvous {
  const BleRendezvous({
    required this.deviceName,
    required this.deviceId,
    this.host,
    this.port,
    this.nonce,
    this.hotspotSsid,
    this.hotspotPsk,
    this.os = 'unknown',
    this.rssi,
  });

  /// Advertised device name. Untrusted; sanitised before display.
  final String deviceName;

  /// Advertised device id. Untrusted, but the only handle for deduplication.
  final String deviceId;

  /// An IP address the peer says it can be reached at, or null when the
  /// rendezvous is only handing over hotspot credentials.
  final String? host;

  /// The port the peer's transport listens on, when known.
  final int? port;

  /// The peer's session nonce, when supplied. Used only to *seed* the SAS once
  /// the real handshake confirms it, never trusted on its own.
  final String? nonce;

  /// Hotspot credentials, when this rendezvous exists to hand those over (the
  /// "no shared subnet" case). The joining device uses these to connect, after
  /// which discovery runs normally.
  final String? hotspotSsid;
  final String? hotspotPsk;

  /// Advertised OS, for the peer list.
  final String os;

  /// Signal strength, when the platform reported it. Useful for ordering
  /// multiple candidates by proximity.
  final int? rssi;

  /// True when this carries a dialable endpoint directly.
  bool get hasEndpoint => (host?.isNotEmpty ?? false) && (port ?? 0) > 0;

  /// True when this carries hotspot credentials to join.
  bool get hasHotspot => hotspotSsid?.isNotEmpty ?? false;

  /// Whether there is anything actionable at all. A rendezvous that is neither
  /// an endpoint nor a hotspot is noise and must be dropped rather than shown.
  bool get isActionable => hasEndpoint || hasHotspot;

  Map<String, dynamic> toJson() => {
        'deviceName': deviceName,
        'deviceId': deviceId,
        if (host != null) 'host': host,
        if (port != null) 'port': port,
        if (nonce != null) 'nonce': nonce,
        if (hotspotSsid != null) 'hotspotSsid': hotspotSsid,
        if (hotspotPsk != null) 'hotspotPsk': hotspotPsk,
        'os': os,
        if (rssi != null) 'rssi': rssi,
      };

  /// Parse an untrusted payload into a sanitised rendezvous.
  ///
  /// Returns null when the payload has no usable device id or nothing
  /// actionable. Every string is clipped and stripped, because this arrives
  /// over an unauthenticated radio channel and is rendered in the UI.
  static BleRendezvous? tryFromJson(Object? raw) {
    if (raw is! Map) return null;
    final map = raw.cast<Object?, Object?>();

    String str(String key, int max) {
      final v = map[key];
      if (v is! String) return '';
      return sanitizeBleText(v, max);
    }

    final deviceId = str('deviceId', 64);
    if (deviceId.isEmpty) {
      coreLog.fine('Dropping a BLE rendezvous with no usable device id.');
      return null;
    }

    final hostRaw = str('host', 64);
    final host = isValidDialableHost(hostRaw) ? hostRaw : null;
    final portRaw = map['port'];
    final port = portRaw is num ? portRaw.toInt() : int.tryParse('$portRaw');
    final port2 = (port != null && port > 0 && port < 65536) ? port : null;

    final ssid = str('hotspotSsid', 48);
    final psk = str('hotspotPsk', 64);
    final nonce = str('nonce', 64);

    final rendezvous = BleRendezvous(
      deviceName: str('deviceName', 80),
      deviceId: deviceId,
      host: host,
      port: port2,
      nonce: nonce.isEmpty ? null : nonce,
      hotspotSsid: ssid.isEmpty ? null : ssid,
      hotspotPsk: psk.isEmpty ? null : psk,
      os: str('os', 16),
      rssi: map['rssi'] is num ? (map['rssi'] as num).toInt() : null,
    );

    if (!rendezvous.isActionable) {
      coreLog.fine('Dropping a BLE rendezvous from $deviceId with no endpoint '
          'and no hotspot credentials.');
      return null;
    }
    return rendezvous;
  }

  @override
  String toString() => 'BleRendezvous($deviceName, $deviceId, '
      '${hasEndpoint ? '$host:$port' : 'no endpoint'}'
      '${hasHotspot ? ', hs=$hotspotSsid' : ''})';
}

/// Strip control and bidi characters and cap length on untrusted BLE text.
///
/// Same rigour as the mDNS layer, for the same reason: a device name is rendered
/// in the peer list, and a right-to-left override would let a peer spoof the
/// order of a UI row.
String sanitizeBleText(String raw, int maxRunes) {
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

/// Whether [host] is a plausible dialable address.
///
/// Validates an IP literal only. A hostname would require DNS, which is exactly
/// the thing that may be broken, and a `.local` name needs multicast, which is
/// what we are trying to route around. Loopback and the unspecified address are
/// refused: a peer advertising `127.0.0.1` would make this device dial itself.
bool isValidDialableHost(String host) {
  if (host.isEmpty || host.length > 64) return false;
  // Refuse anything with a scheme, path, or whitespace: this string is used to
  // construct a connection target, and a value like `evil.com/x` must not slip
  // through as a "host".
  if (RegExp(r'[\s/\\]').hasMatch(host)) return false;

  // `InternetAddress.tryParse` accepts an IPv4 or IPv6 literal and nothing else,
  // which is exactly the contract wanted here. A name is not an error to
  // tolerate: it is an address we cannot use without DNS.
  final address = InternetAddress.tryParse(host);
  if (address == null) return false;
  if (address.isLoopback || address.isLinkLocal) return false;
  if (address.rawAddress.every((b) => b == 0)) return false;
  if (address.type == InternetAddressType.IPv6) {
    if (address.rawAddress.first == 0xff) return false;
  } else if (address.rawAddress.first >= 224 && address.rawAddress.first <= 239) {
    return false;
  }
  return true;
}

/// Hosts a BLE rendezvous advertisement (peripheral role).
///
/// Android implements this. The advertisement is tiny by design: a fixed Aero
/// service UUID plus a short rendezvous id; the actual payload is served over a
/// GATT characteristic once a central connects, because a legacy BLE
/// advertisement cannot fit a URL, an SSID, and a passphrase.
abstract class BleAdvertiser {
  /// Whether this platform can advertise at all.
  bool get isSupported;

  /// A sentence explaining why advertising is unavailable, or null.
  String? get unsupportedReason;

  /// Begin advertising [payload] under [rendezvousId].
  ///
  /// [rendezvousId] is the short handle placed in the advertisement itself; a
  /// central that is interested connects and reads the full payload.
  Future<void> start({
    required String rendezvousId,
    required BleRendezvous payload,
  });

  /// Stop advertising. Safe when not started.
  Future<void> stop();

  /// True between a successful [start] and [stop].
  bool get isAdvertising;
}

/// Scans for a BLE rendezvous advertisement (central role).
///
/// macOS implements this. Scanning is the reliable direction on Apple platforms;
/// a sandboxed Mac app is a central, and Android peripheral advertising is
/// universally supported, so the roles do not need to be symmetric.
abstract class BleScanner {
  /// Whether this platform can scan at all.
  bool get isSupported;

  /// A sentence explaining why scanning is unavailable, or null.
  String? get unsupportedReason;

  /// Scan until a peer is found or [timeout] elapses.
  ///
  /// Returns the first actionable rendezvous, or null on timeout. Failure is
  /// reported through [BleException] so the caller can distinguish "nothing
  /// found" from "Bluetooth is off".
  Future<BleRendezvous?> scanOnce({Duration timeout});

  /// Stop scanning. Safe when not started.
  Future<void> stop();
}

/// A [BleAdvertiser] for platforms that cannot advertise.
class UnsupportedBleAdvertiser implements BleAdvertiser {
  const UnsupportedBleAdvertiser(this.unsupportedReason);

  @override
  final String? unsupportedReason;

  @override
  bool get isSupported => false;

  @override
  bool get isAdvertising => false;

  @override
  Future<void> start({
    required String rendezvousId,
    required BleRendezvous payload,
  }) async {
    throw BleException(
      BleFailure.unsupported,
      unsupportedReason ?? 'This device cannot advertise over Bluetooth.',
    );
  }

  @override
  Future<void> stop() async {}
}

/// A [BleScanner] for platforms that cannot scan.
class UnsupportedBleScanner implements BleScanner {
  const UnsupportedBleScanner(this.unsupportedReason);

  @override
  final String? unsupportedReason;

  @override
  bool get isSupported => false;

  @override
  Future<BleRendezvous?> scanOnce({Duration timeout = const Duration(seconds: 20)}) async {
    throw BleException(
      BleFailure.unsupported,
      unsupportedReason ?? 'This device cannot scan over Bluetooth.',
    );
  }

  @override
  Future<void> stop() async {}
}

/// Whether a device can advertise or scan over BLE, and if not, why.
///
/// Shared by both platform implementations so the capability shape is identical
/// whether it came from Android's `BluetoothAdapter` or macOS's `CBManagerState`.
class BleCapability {
  const BleCapability({
    required this.supported,
    this.reason = '',
    this.permission = '',
  });

  final bool supported;

  /// Human-readable explanation when [supported] is false.
  final String reason;

  /// The runtime permission this platform requires, if any.
  final String permission;

  Map<String, dynamic> toJson() => {
        'supported': supported,
        'reason': reason,
        'permission': permission,
      };

  @override
  String toString() =>
      'BleCapability(supported=$supported${reason.isEmpty ? '' : ', $reason'})';
}
