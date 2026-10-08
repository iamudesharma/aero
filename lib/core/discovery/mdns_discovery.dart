/// mDNS / DNS-SD discovery over `package:bonsoir`.
///
/// # Why this file is mostly defensive code
///
/// mDNS is **unauthenticated broadcast**. Every field of every record that
/// arrives on [DiscoveryService.peers] was typed by a stranger on the same
/// Ethernet segment, so it is treated as hostile input rather than as a fact:
///   * the device name is stripped of control / bidi characters and truncated,
///     because it is rendered in the peer list and a right-to-left override
///     would let a peer spoof the *order* of the UI row;
///   * a missing or unparseable port falls back to [kPreferredPort] instead of
///     throwing, because an exception in the middle of a resolve callback would
///     kill the discovery stream and take browsing down with it;
///   * a peer that does not advertise a `deviceId` is **dropped**: we could not
///     deduplicate it, could not recognise our own echo, and could not pin it.
///   * our own advertisement is filtered out by comparing the TXT `id` with our
///     own, because every mDNS responder sees itself.
///
/// # bonsoir 7.x API, as actually shipped
///
/// This is the *7.x* API, which differs substantially from the 5.x/6.x one:
///
/// ```dart
/// final broadcast  = BonsoirBroadcast(service: service); // not Bonsoir.registerService
/// await broadcast.initialize();
/// broadcast.eventStream?.listen(...); // eventStream is null until initialize()
/// await broadcast.start();
///
/// final discovery = BonsoirDiscovery(type: kServiceType); // not BonsoirBrowser
/// await discovery.initialize();
/// discovery.eventStream!.listen(...);
/// await discovery.start();
/// await discovery.serviceResolver.resolveService(service);
/// ```
///
/// There is no `Bonsoir` singleton, no `BonsoirBrowser`, and no
/// `BonsoirServiceRegistration` in 7.x. The two roles are `BonsoirBroadcast`
/// and `BonsoirDiscovery`, both wrapping a `BonsoirActionHandler<T>` that offers
/// only `initialize / start / stop / isReady / isStopped / eventStream`.
/// Consequences that shape this class:
///
///   * **Actions are one-shot.** `MethodChannelBonsoirAction.start()` asserts
///     `!isStopped`, so a stopped action can never be restarted - re-advertising
///     a different port requires building an entirely new `BonsoirBroadcast`.
///     See [updateAdvertisedPort].
///   * **Native failures are stream errors, not thrown futures.**
///     `onError(...)` on the Swift/Kotlin side pushes a `FlutterError` down the
///     event channel, which surfaces in Dart as an error on `eventStream`. A
///     `try`/`catch` around `start()` therefore catches almost nothing on its
///     own; every listener needs an `onError` callback or a denied local-network
///     permission vanishes without a trace.
///   * **The domain is not configurable.** Darwin registers in `local.` and
///     browses `.bonjourWithTXTRecord(type:domain: "local.")`. [kServiceDomain]
///     is therefore documentation/diagnostics only, not something we pass in.
///   * **There is no name normalisation worth relying on.**
///     `BonsoirServiceNormalizer.normalizeName` intends to strip control
///     characters but the result of its `replaceAll` is discarded, so control
///     characters survive. We sanitise the name ourselves before handing it over.
///   * **`normalizeAttributes` truncates each `key=value` to 255 bytes by
///     chopping UTF-16 code units**, which can split a surrogate pair and emit
///     mojibake. Our own byte caps keep us below that path entirely.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:bonsoir/bonsoir.dart';
import 'package:flutter/foundation.dart' show kIsWeb;

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';

// ---------------------------------------------------------------------------
// Limits applied to peer-supplied strings
// ---------------------------------------------------------------------------

/// Longest device name kept, in runes. 80 is generous for a hostname-style label
/// and keeps the TXT record comfortably inside one multicast datagram.
const int kMaxDeviceNameRunes = 80;

/// Longest device name, in UTF-8 bytes, that we put in our *own* TXT record.
///
/// RFC 6763 section 6 caps each constituent string of a DNS TXT record at 255
/// bytes; bonsoir enforces that by trimming one UTF-16 code unit at a time, which
/// can split a surrogate pair. Pre-truncating on a rune boundary keeps the value
/// well clear of that path.
const int kMaxDeviceNameBytes = 200;

/// RFC 6763 section 4.1.1: a DNS-SD instance name must not exceed 63 bytes.
const int kMaxServiceNameBytes = 63;

/// Rune cap matching [kMaxServiceNameBytes]; the byte cap is the real limit.
const int kMaxServiceNameRunes = 63;

/// Device ids are 128-bit handles rendered as 32 hex characters. 64 runes is a
/// generous ceiling that still bounds what a hostile peer can make us store or
/// render.
const int kMaxDeviceIdRunes = 64;

/// Cap on the `osv` / `app` values we advertise and consume. Neither needs to be
/// long, and an unbounded peer-supplied string would be a silly thing to carry in
/// a TXT record.
const int kMaxShortVersionRunes = 40;

/// Most capability tokens we will parse out of one TXT value. Guards against a
/// peer that fills the record with thousands of commas.
const int kMaxCapabilities = 16;

/// How many distinct service names we remember for diagnostics. A hostile LAN can
/// announce services forever; this must not be an unbounded set.
const int kMaxRememberedNames = 48;

/// How many live peers we keep for periodic re-resolution, same reasoning.
const int kMaxTrackedServices = 64;

/// How often we re-resolve known peers. A resolve refreshes the `resolvedAt`
/// stamp the UI expires on, so a peer that keeps answering stays visible and one
/// that has quietly left the network stops being refreshed and ages out.
const Duration kRefreshInterval = Duration(seconds: 30);

/// How long we wait for the first confirmation event from a native
/// register/browse before assuming it is merely silent rather than working.
///
/// On macOS a missing `NSLocalNetworkUsageDescription` makes the whole operation
/// fail *silently* - no error, no callback - so a timeout is the only signal we
/// get, and it must not be reported as success.
const Duration kStartupTimeout = Duration(seconds: 6);

/// After this long with a running browser and zero answers we add an explicit
/// hint to [MdnsDiscovery.diagnostics], because "no peers" and "you have no
/// local network permission" are otherwise indistinguishable in the UI.
const Duration kSilentHintDelay = Duration(seconds: 12);

/// Fallback shown when a peer advertises a name that sanitises away to nothing.
const String kUnknownDeviceName = 'Unknown device';

/// Last-resort DNS-SD instance name. Bonsoir substitutes `My service` for an
/// empty name, which would be a confusing thing to see in another device's peer
/// list.
const String kFallbackServiceName = 'Aero device';

/// C0 controls, DEL, and the C1 range. In UTF-16 these are all single units, so a
/// plain regular expression is safe.
final RegExp _controlChars = RegExp(r'[\x00-\x1F\x7F\x80-\x9F]');

/// Invisible formatting characters.
///
/// U+202E (RIGHT-TO-LEFT OVERRIDE) is the important one: a peer could advertise
/// `"\u202Eexe.dmg"` and have a file-ish string render before the real name, so
/// the UI shows something that is not the name. ZWSP / soft hyphen / BOM are
/// stripped because they break naive string comparison and search.
final RegExp _formatChars =
    RegExp('[\u200B-\u200F\u202A-\u202E\u2066-\u2069\u00AD\uFEFF]');

/// Runs of whitespace, collapsed to a single space. Keeps a name that arrived as
/// `"my   \n laptop"` from turning into a ragged UI row.
final RegExp _whitespaceRun = RegExp(r'\s+');

/// Trailing dots, which bonsoir explicitly warns are mishandled on Windows.
final RegExp _trailingDots = RegExp(r'\.+$');

/// Anything outside printable ASCII, for the ASCII-only retry name.
final RegExp _nonAsciiPrintable = RegExp(r'[^ -~]');

// ---------------------------------------------------------------------------
// Hostile-input sanitisation
// ---------------------------------------------------------------------------

/// Truncate to at most [maxRunes] runes.
///
/// Deliberately rune-based rather than `String.substring`, which cuts UTF-16 code
/// units and can leave a lone surrogate at the end - producing a string Dart will
/// then refuse to encode for the wire.
String truncateRunes(String value, int maxRunes) {
  if (maxRunes <= 0) return '';
  var seen = 0;
  final out = <int>[];
  for (final rune in value.runes) {
    if (seen >= maxRunes) break;
    out.add(rune);
    seen++;
  }
  return String.fromCharCodes(out);
}

/// Truncate to at most [maxBytes] when UTF-8 encoded, never splitting a rune.
///
/// mDNS TXT strings and DNS labels are byte-limited, not character-limited.
String truncateUtf8(String value, int maxBytes) {
  if (maxBytes <= 0) return '';
  if (utf8.encode(value).length <= maxBytes) return value;
  var used = 0;
  final out = StringBuffer();
  for (final rune in value.runes) {
    final size = utf8.encode(String.fromCharCode(rune)).length;
    if (used + size > maxBytes) break;
    out.writeCharCode(rune);
    used += size;
  }
  return out.toString();
}

/// Strip control characters, bidi overrides, and redundant whitespace.
String stripUnsafeText(String value) =>
    value.replaceAll(_controlChars, '').replaceAll(_formatChars, '');

/// Make a peer-supplied device name safe to render and to put in a TXT record.
///
/// Returns [kUnknownDeviceName] rather than an empty string: a peer that
/// advertises `name=` (or a name made entirely of control characters) must still
/// produce a visible, attributable row rather than a blank one.
String sanitizeDeviceName(String raw, {int maxRunes = kMaxDeviceNameRunes}) {
  var text = stripUnsafeText(raw).replaceAll(_whitespaceRun, ' ').trim();
  if (text.isEmpty) return kUnknownDeviceName;
  text = truncateRunes(text, maxRunes);
  // The byte cap can still bite on non-ASCII names, and it can leave a trailing
  // space behind, which we then trim.
  text = truncateUtf8(text, kMaxDeviceNameBytes).trimRight();
  return text.isEmpty ? kUnknownDeviceName : text;
}

/// Make a device name safe to advertise as a DNS-SD *instance* name.
///
/// Two things make this stricter than [sanitizeDeviceName]:
///   * the 63-byte cap from RFC 6763 section 4.1.1;
///   * [asciiOnly], used for the single sanitise-and-retry attempt when bonsoir
///     or the platform rejects the name. Windows' DNS-SD shim and several
///     middleboxes mangle non-ASCII instance names, so when in doubt the name
///     has to be boring.
String sanitizeServiceName(String raw, {bool asciiOnly = false}) {
  var text = stripUnsafeText(raw).replaceAll(_whitespaceRun, ' ').trim();
  if (asciiOnly) {
    // Fold to a space first, then collapse, so `Bücher` becomes `B cher`
    // rather than `Bcher` - a hyphen would read like a real separator.
    text = text.replaceAll(_nonAsciiPrintable, ' ').replaceAll(_whitespaceRun, ' ').trim();
  }
  text = text.replaceAll(_trailingDots, '').trim();
  text = truncateRunes(text, kMaxServiceNameRunes);
  text = truncateUtf8(text, kMaxServiceNameBytes).trim();
  return text.isEmpty ? kFallbackServiceName : text;
}

/// Make a peer-supplied device id safe to use as a map key, a log field, and a
/// UI string.
///
/// The character set is deliberately *not* restricted to hex: a future protocol
/// revision may use uuid-with-dashes or base64url, and rejecting a legitimate
/// peer because of its id format would be a bad trade. What we do remove is
/// anything that can corrupt a UI row or a log line, plus runaway length.
String sanitizeDeviceId(String raw, {int maxRunes = kMaxDeviceIdRunes}) =>
    truncateRunes(stripUnsafeText(raw).trim(), maxRunes);

/// Cap a short version-ish string (os version, app version).
String sanitizeShortVersion(String raw, {int maxRunes = kMaxShortVersionRunes}) =>
    truncateRunes(stripUnsafeText(raw).trim(), maxRunes);

/// True when [port] is a usable TCP port.
bool isValidPort(int? port) => port != null && port > 0 && port < 65536;

/// Read a port out of a TXT value, falling back sensibly.
///
/// Order of trust: the TXT `port` (what the peer says it is listening on, and
/// what the rest of the protocol is built around), then the SRV port that the
/// resolver handed us for this service, then [kPreferredPort]. A peer that sends
/// `port=not-a-number`, `port=0`, `port=99999`, or omits the key entirely must
/// not be able to break parsing.
int parseAdvertisedPort(String? raw, {int? fallback}) {
  final text = raw?.trim() ?? '';
  if (text.isNotEmpty) {
    final parsed = int.tryParse(text);
    if (isValidPort(parsed)) return parsed!;
    coreLog.fine('Ignoring unusable advertised port "$text".');
  }
  return isValidPort(fallback) ? fallback! : kPreferredPort;
}

/// Parse the comma-separated `caps` TXT value into a set of capabilities.
///
/// Unknown tokens are dropped rather than throwing: a peer from a future
/// protocol version may advertise capabilities we do not know, and refusing to
/// show it would be worse than ignoring the extra tokens.
Set<Capability> parseCapabilities(String? raw) {
  if (raw == null || raw.isEmpty) return const <Capability>{};
  final out = <Capability>{};
  for (final token in raw.split(',')) {
    if (out.length >= kMaxCapabilities) break;
    final capability = Capability.fromName(token.trim());
    if (capability != null) out.add(capability);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Address selection
// ---------------------------------------------------------------------------

/// Whether [address] is worth handing to a dialer.
///
/// Rejects, in order of why:
///   * unspecified addresses (`0.0.0.0`, `::`) - a peer that advertises the
///     wildcard is telling us it has no address, not that we should dial it;
///   * loopback - it would resolve to *us*, and mDNS already reports the LAN
///     address of a same-host service, so preferring it here would make a
///     cross-device transfer silently become a loopback one;
///   * IPv4 link-local (`169.254/16`) and IPv6 link-local (`fe80::/10`) - both
///     need an interface scope id that [PeerAddress] has nowhere to carry, and
///     `fe80::` in particular produces a URI that parses but cannot connect;
///   * multicast, which a peer has no business advertising.
bool isDialableHostAddress(InternetAddress address) {
  if (address.address.isEmpty) return false;
  if (address.rawAddress.isEmpty) return false;
  // dart:io has isLoopback and isLinkLocal but no isUnspecified, so the wildcard
  // check is written out here.
  if (address.rawAddress.every((byte) => byte == 0)) return false;
  if (address.isLoopback || address.isLinkLocal) return false;
  if (address.type == InternetAddressType.IPv6) {
    // ff00::/8 - IPv6 multicast. dart:io exposes no isMulticast for IPv6.
    if (address.rawAddress.first == 0xff) return false;
  } else if (address.rawAddress.first >= 224 && address.rawAddress.first <= 239) {
    // 224.0.0.0/4 - IPv4 multicast.
    return false;
  }
  return true;
}

/// Pick the single address to dial from a resolved service's addresses.
///
/// **One peer per service instance, one address per peer.** A dual-stack machine
/// advertises an IPv4 and one or more IPv6 addresses; emitting a peer per address
/// would make the UI list the same device three times and would triple the number
/// of connections the user can accidentally open. The UI deduplicates by
/// `deviceId` (see [DiscoveryService.peers]), so a second `DiscoveredPeer` for the
/// same device would simply overwrite the first - but which address survived
/// would then depend on resolution order.
///
/// IPv4 is preferred because it is the address family that is unambiguous here:
/// no scope id, no interface index, and no chance of a link-local `fe80::` being
/// chosen ahead of something dialable. A global IPv6 (or ULA `fd00::/8`) address
/// is used when the service offers nothing else, which does happen on
/// IPv6-only LANs.
///
/// Accepts IPv4 or IPv6 in either order.
InternetAddress? selectHostAddress(List<InternetAddress> addresses) {
  InternetAddress? bestIpv6;
  for (final address in addresses) {
    if (!isDialableHostAddress(address)) continue;
    if (address.type == InternetAddressType.IPv4) return address;
    bestIpv6 ??= address;
  }
  return bestIpv6;
}

// ---------------------------------------------------------------------------
// TXT parsing (pure, and therefore unit-testable without touching the network)
// ---------------------------------------------------------------------------

/// Turn one resolved mDNS service into a [DiscoveredPeer], or `null` if it is not
/// something we are willing to show.
///
/// Returns `null` when:
///   * [attributes] carries no usable `id` - we could not deduplicate it, could
///     not recognise our own echo, and could never pin its key;
///   * the advertised id equals [selfDeviceId] - our own advertisement;
///   * none of [addresses] is dialable (see [selectHostAddress]).
///
/// Everything else is treated as *claims*, not facts: [PeerInfo.trustState] stays
/// [TrustState.unknown] (the default) and `publicKey` / `nonce` are left empty
/// because those must come from `GET /v1/info` over an authenticated channel -
/// the TXT record is exactly the place an attacker can write whatever they like.
///
/// [servicePort] is the SRV port the resolver reported. It is only consulted when
/// the TXT `port` is missing or unusable, and a disagreement between the two is
/// logged, because a peer whose SRV and TXT ports differ is either broken or
/// trying to be confusing.
DiscoveredPeer? parseResolvedService(
  Map<String, String> attributes,
  List<InternetAddress> addresses,
  String selfDeviceId, {
  int? servicePort,
  DateTime? now,
}) {
  final selfId = sanitizeDeviceId(selfDeviceId);
  final deviceId = sanitizeDeviceId(attributes[TxtKey.deviceId] ?? '');
  if (deviceId.isEmpty) {
    coreLog.fine('Dropping a service that advertised no usable device id.');
    return null;
  }
  // Our own advertisement is always visible to us, and on Darwin the browsed
  // service list contains it. Filtering on the TXT id is the only reliable test:
  // the instance name may have been auto-renamed on a name conflict.
  if (selfId.isNotEmpty && deviceId == selfId) {
    coreLog.fine('Dropping our own advertisement.');
    return null;
  }

  final host = selectHostAddress(addresses);
  if (host == null) {
    coreLog.fine('Dropping $deviceId: no dialable address in '
        '${addresses.map((a) => a.address).toList()}.');
    return null;
  }

  final txtPort = _validParsedPort(attributes[TxtKey.port]);
  if (txtPort != null && isValidPort(servicePort) && txtPort != servicePort) {
    // SRV is what a connection actually lands on; TXT is what a peer list shows.
    // When they disagree the transport's dial will fail, so surface it.
    coreLog.warning('Peer $deviceId advertises port $txtPort but its SRV record '
        'says ${servicePort!}; trusting the TXT value.');
  }
  final port = parseAdvertisedPort(attributes[TxtKey.port], fallback: servicePort);

  final info = PeerInfo(
    deviceId: deviceId,
    deviceName: sanitizeDeviceName(attributes[TxtKey.deviceName] ?? ''),
    os: aeroOsFromName((attributes[TxtKey.os] ?? '').trim().toLowerCase()),
    osVersion: sanitizeShortVersion(attributes[TxtKey.osVersion] ?? ''),
    appVersion: sanitizeShortVersion(attributes[TxtKey.appVersion] ?? ''),
    // Deliberately empty: the real key arrives from GET /v1/info over the
    // authenticated transport, and the TXT hash is not a key.
    publicKey: '',
    // Garbage becomes 0, which reads as "incompatible" in the UI rather than
    // accidentally matching our version.
    protocolVersion: _validProtocolVersion(attributes[TxtKey.protocol]),
    capabilities: parseCapabilities(attributes[TxtKey.capabilities]),
    // Fresh per session, learned from GET /v1/info; never from a TXT record.
    nonce: '',
    port: port,
    // The only pre-pairing handle on the peer's identity. Untrusted (mDNS is
    // unauthenticated) but enough to notice that a device we have paired with
    // before is now presenting a different key, which is exactly the case the
    // user needs to be warned about *before* they compare a code.
    publicKeyHash: sanitizeShortVersion(attributes[TxtKey.publicKeyHash] ?? ''),
  );

  return DiscoveredPeer(
    info: info,
    address: PeerAddress(host: host.address, port: port),
    resolvedAt: now ?? DateTime.now(),
  );
}

int? _validParsedPort(String? raw) {
  final text = raw?.trim() ?? '';
  if (text.isEmpty) return null;
  final parsed = int.tryParse(text);
  return isValidPort(parsed) ? parsed : null;
}

int _validProtocolVersion(String? raw) {
  final text = raw?.trim() ?? '';
  if (text.isEmpty) return 0;
  final parsed = int.tryParse(text);
  if (parsed == null || parsed < 0 || parsed > 999) return 0;
  return parsed;
}

// ---------------------------------------------------------------------------
// The DiscoveryService implementation
// ---------------------------------------------------------------------------

enum _AdvertiseState {
  idle('not started'),
  advertising('advertising'),
  unconfirmed('advertising (unconfirmed)'),
  failed('failed'),
  stopped('stopped');

  const _AdvertiseState(this.label);

  final String label;
}

enum _BrowseState {
  idle('not started'),
  initialising('initialising'),
  browsing('browsing'),
  stopped('stopped'),
  failed('failed');

  const _BrowseState(this.label);

  final String label;
}

/// Publishes this device over mDNS/DNS-SD and streams back the peers it finds.
///
/// See the file header for why so much of this is validation. Everything
/// user-visible about "why am I seeing nothing" is exposed through
/// [unavailableReason] and [diagnostics], because mDNS's most common failure mode
/// - denied local-network permission - produces no error at all.
class MdnsDiscovery implements DiscoveryService {
  /// Creates a discovery backend. Nothing touches the network until [start].
  MdnsDiscovery();

  final StreamController<DiscoveredPeer> _peers =
      StreamController<DiscoveredPeer>.broadcast();

  BonsoirBroadcast? _broadcast;
  StreamSubscription<BonsoirBroadcastEvent>? _broadcastSub;
  BonsoirDiscovery? _discovery;
  StreamSubscription<BonsoirDiscoveryEvent>? _discoverySub;
  Timer? _refreshTimer;

  PeerInfo? _self;
  int? _advertisedPort;
  int? _registeredPort;
  bool _running = false;
  bool _disposed = false;
  String? _failure;

  _AdvertiseState _advertise = _AdvertiseState.idle;
  _BrowseState _browse = _BrowseState.idle;
  bool _serviceTypeOk = true;
  String _interfaces = 'unknown';
  DateTime? _startedAt;
  DateTime? _lastEventAt;
  String _lastEvent = 'never';
  String? _lastError;

  final Map<String, BonsoirService> _liveServices = <String, BonsoirService>{};
  final LinkedHashSet<String> _seenNames = LinkedHashSet<String>();

  int _servicesSeen = 0;
  int _peersEmitted = 0;
  int _foundEvents = 0;
  int _resolvedEvents = 0;
  int _lostEvents = 0;
  int _selfFiltered = 0;
  int _rejectedNoId = 0;
  int _rejectedNoAddress = 0;
  int _resolveRequests = 0;
  int _resolveFailures = 0;
  int _nameConflicts = 0;

  @override
  String get backendName => 'mdns (bonsoir)';

  /// `null` while discovery is working; otherwise a sentence the UI can show.
  ///
  /// Only meaningful between [start] and [stop]: before [start] and after [stop]
  /// there is nothing running, so there is nothing to be broken about. The
  /// persistent record of what went wrong stays available in [diagnostics].
  @override
  String? get unavailableReason => _running ? _failure : null;

  @override
  Stream<DiscoveredPeer> get peers => _peers.stream;

  /// A snapshot for the diagnostics panel.
  ///
  /// The point of this map is the macOS case: a missing
  /// `NSLocalNetworkUsageDescription` (or a denied prompt) makes Bonjour fail
  /// *silently* - the browser starts, reports ready, and then simply never sees a
  /// single peer. Without these counters that is indistinguishable from an empty
  /// room, so the UI can say something useful instead of "no peers found".
  Map<String, String> get diagnostics => <String, String>{
        'backend': backendName,
        'serviceType': kServiceType,
        // kServiceDomain cannot be passed to bonsoir 7.x; Darwin hardcodes
        // `local.` on both the register and the browse side. Recorded here so
        // that the mismatch between our constant and the plugin is visible.
        'domain': '$kServiceDomain (hardcoded by bonsoir, not settable)',
        'serviceTypeRfcConformant': '$_serviceTypeOk',
        'running': '$_running',
        'advertise': _advertise.label,
        'advertisedPort': '${_registeredPort ?? _advertisedPort ?? '-'}',
        'browse': _browse.label,
        'browserReady': '${_discovery?.isReady ?? false}',
        'unavailableReason': _failure ?? 'none',
        'interfaces': _interfaces,
        'servicesSeen': '$_servicesSeen',
        'peersEmitted': '$_peersEmitted',
        'foundEvents': '$_foundEvents',
        'resolvedEvents': '$_resolvedEvents',
        'lostEvents': '$_lostEvents',
        'selfFiltered': '$_selfFiltered',
        'rejectedNoId': '$_rejectedNoId',
        'rejectedNoAddress': '$_rejectedNoAddress',
        'resolveRequests': '$_resolveRequests',
        'resolveFailures': '$_resolveFailures',
        'nameConflicts': '$_nameConflicts',
        'trackedServices': '${_liveServices.length}',
        'lastEvent': _lastEvent,
        'lastEventAgo': _ago(_lastEventAt),
        'uptime': _ago(_startedAt),
        'lastError': _lastError ?? 'none',
        'hint': ?_hint(),
      };

  @override
  Future<void> start({required int port, required PeerInfo self}) async {
    if (_disposed) {
      throw StateError('MdnsDiscovery.start() was called after dispose().');
    }
    // Restarting is a stop followed by a start, so a caller that re-enters
    // start() does not end up with two browsers fighting over one port.
    await stop();

    _self = self;
    _advertisedPort = port;
    _failure = null;
    _running = true;
    _startedAt = DateTime.now();
    _lastEvent = 'starting';

    if (kIsWeb) {
      // bonsoir has no web platform implementation; the default method-channel
      // instance would fail later with a MissingPluginException and a far less
      // helpful message.
      _fail('mDNS / DNS-SD is not available in a browser. Use the native build '
          'on the same network, or a transport that reaches peers from the web.');
      return;
    }

    await _probeInterfaces();
    if (_failure != null) return;

    _serviceTypeOk = BonsoirServiceNormalizer.normalizeType(kServiceType) == kServiceType;
    if (!_serviceTypeOk) {
      coreLog.warning('kServiceType "$kServiceType" is not RFC 6335 conformant; '
          'bonsoir will browse '
          '"${BonsoirServiceNormalizer.normalizeType(kServiceType)}" instead, '
          'which must also appear in NSBonjourServices.');
    }

    // Advertise before browsing: if we cannot register at all, peers will never
    // reach us, and the user deserves to be told rather than to watch an empty
    // list with an explanation that cannot possibly be true.
    var outcome = await _registerBroadcast(port, hardSanitise: false);
    if (outcome == _AdvertiseResult.failed) {
      coreLog.info('Retrying the mDNS registration with an ASCII-only name.');
      outcome = await _registerBroadcast(port, hardSanitise: true);
    }
    switch (outcome) {
      case _AdvertiseResult.started:
        _advertise = _AdvertiseState.advertising;
      case _AdvertiseResult.unconfirmed:
        _advertise = _AdvertiseState.unconfirmed;
        // Surfaced through `unavailableReason`, not just logged. A registration
        // that produces no confirmation within the timeout is the *documented*
        // symptom of a denied macOS local-network permission, and without this
        // the UI falls back to "searching for devices", which is actively
        // misleading: the device is not searching, it is invisible.
        _fail(
          'This device could not be advertised on the local network '
          '(no confirmation from mDNS within ${kStartupTimeout.inSeconds}s). '
          'On macOS this almost always means Aero does not have Local Network '
          'access: open System Settings → Privacy & Security → Local Network '
          'and enable Aero, then relaunch. Without it other devices cannot see '
          'this one.',
        );
      case _AdvertiseResult.failed:
        _advertise = _AdvertiseState.failed;
        _fail('This device could not be advertised on the local network'
            '${_lastError == null ? '' : ' (${_lastError!})'}. Other devices '
            'cannot reach it until this is resolved.');
    }

    // Browsing is still attempted: a device that cannot advertise may well be
    // able to discover, and finding peers is more useful than nothing.
    //
    // Wrapped because on Android `discovery.start` reaches a native plugin whose
    // failures arrive asynchronously, and on some devices a TXT-record query
    // raises a `PlatformException`/`Error` that is NOT an `Exception` — so a
    // plain try/catch downstream misses it and the whole process dies. Losing
    // browsing must degrade to "this device cannot be seen and cannot see
    // others", never to a crash.
    try {
      await _startDiscovery();
    } catch (error, stack) {
      _fail(
        'Local network discovery could not start on this device ($error). '
        'Aero can still receive if a peer connects directly.',
      );
      coreLog.warning('discovery start failed', error, stack);
    }
  }

  @override
  Future<void> stop() async {
    _running = false;
    _refreshTimer?.cancel();
    _refreshTimer = null;
    await _dropBroadcast();
    await _dropDiscovery();
    _liveServices.clear();
    _advertise = _AdvertiseState.stopped;
    _browse = _BrowseState.stopped;
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    await stop();
    _disposed = true;
    await _peers.close();
  }

  /// Re-advertise with a new port.
  ///
  /// The transport binds an ephemeral port when [kPreferredPort] is taken, so the
  /// port in the TXT record has to follow reality rather than being assumed.
  ///
  /// bonsoir limitation: a `BonsoirBroadcast` is one-shot. `start()` asserts
  /// `!isStopped`, so the old action is torn down and a brand new one is built
  /// (a new instance, a new native id, a fresh registration). Peers therefore see
  /// a brief withdraw/announce gap, and if the new registration fails we are left
  /// unadvertised rather than advertising a stale port - which is the honest
  /// failure mode, since a wrong port is indistinguishable from being offline.
  Future<void> updateAdvertisedPort(int port) async {
    if (_disposed) {
      throw StateError('MdnsDiscovery.updateAdvertisedPort() was called after dispose().');
    }
    _advertisedPort = port;
    if (!_running || _self == null) {
      // Not advertising yet; [start] will pick the new value up.
      return;
    }
    if (port == _registeredPort && _advertise == _AdvertiseState.advertising) {
      return;
    }

    coreLog.info('Transport bound port $port; re-registering the mDNS service.');
    await _dropBroadcast();

    var outcome = await _registerBroadcast(port, hardSanitise: false);
    if (outcome == _AdvertiseResult.failed) {
      coreLog.info('Re-registration failed; retrying with an ASCII-only name.');
      outcome = await _registerBroadcast(port, hardSanitise: true);
    }
    switch (outcome) {
      case _AdvertiseResult.started:
        _advertise = _AdvertiseState.advertising;
        _registeredPort = port;
      case _AdvertiseResult.unconfirmed:
        // Keep it: an unconfirmed registration may still be live, and tearing it
        // down on a timeout would turn a possibly-fine state into a certain one.
        _advertise = _AdvertiseState.unconfirmed;
        _registeredPort = port;
      case _AdvertiseResult.failed:
        _advertise = _AdvertiseState.failed;
        _fail('The transport moved to port $port but the mDNS service could not '
            'be re-registered'
            '${_lastError == null ? '' : ' (${_lastError!})'}. Other devices '
            'cannot reach this one.');
    }
  }

  // -------------------------------------------------------------------------
  // Local interface probe
  // -------------------------------------------------------------------------

  /// Confirm there is at least one usable LAN interface.
  ///
  /// "No peers found" and "this device has no network" look identical from the
  /// UI, so we make the difference explicit here. A failure to *enumerate*
  /// interfaces is not treated as a failure to have them: some platforms restrict
  /// the call, and guessing "no interfaces" would be worse than staying quiet.
  Future<void> _probeInterfaces() async {
    try {
      final interfaces = await NetworkInterface.list();
      final usable = <String>[];
      for (final interface in interfaces) {
        final addresses = interface.addresses.where(isDialableHostAddress).toList();
        if (addresses.isEmpty) continue;
        usable.add('${interface.name}:${addresses.map((a) => a.address).join('/')}');
      }
      _interfaces = usable.isEmpty ? 'none usable' : usable.join(', ');
      if (usable.isEmpty) {
        _fail('No network interface is usable. Connect to a Wi-Fi or Ethernet '
            'network; mDNS only works on a local link.');
        return;
      }
      coreLog.fine('Usable interfaces: $_interfaces');
    } catch (error) {
      // Not fatal. A restricted platform may refuse the enumeration entirely.
      _interfaces = 'unknown ($error)';
      coreLog.fine('Could not enumerate network interfaces: $error');
    }
  }

  // -------------------------------------------------------------------------
  // Advertising
  // -------------------------------------------------------------------------

  /// Build and start a [BonsoirBroadcast] for [port].
  ///
  /// Returns [started] once the platform confirms the registration,
  /// [unconfirmed] if nothing came back within [kStartupTimeout], and [failed]
  /// after an explicit rejection - which is the case that earns the caller's one
  /// sanitise-and-retry attempt.
  ///
  /// [hardSanitise] switches the instance name to ASCII-only: non-ASCII DNS-SD
  /// instance names are legal in Net-Unicode but are the most common cause of a
  /// registration that works on macOS and fails on Windows.
  Future<_AdvertiseResult> _registerBroadcast(int port, {required bool hardSanitise}) async {
    final self = _self;
    if (self == null) return _AdvertiseResult.failed;

    final name = sanitizeServiceName(self.deviceName, asciiOnly: hardSanitise);
    final BonsoirService service;
    try {
      service = BonsoirService(
        name: name,
        type: kServiceType,
        port: port,
        attributes: _advertisedAttributes(port),
        // hostAddresses and hostname are deliberately left empty. The Darwin
        // backend registers with `hostAddresses.first ?? hostname`, so passing
        // our own address would pin the SRV target to a single interface; empty
        // lets mDNSResponder advertise every interface, which is what we want on
        // a machine that is on Wi-Fi and Ethernet at once.
      );
    } catch (error, stack) {
      coreLog.warning('bonsoir rejected the service name "$name".', error, stack);
      _lastError = 'advertise: rejected service name "$name"';
      return _AdvertiseResult.failed;
    }
    if (service.name != name) {
      // bonsoir substitutes 'My service' for an empty name; our sanitiser never
      // produces one, so any rewrite here is worth knowing about.
      coreLog.warning('bonsoir rewrote the service name "$name" to "${service.name}".');
    }

    final BonsoirBroadcast broadcast;
    try {
      broadcast = BonsoirBroadcast(service: service, printLogs: false);
      // Must be awaited: eventStream is null until the platform action exists.
      await broadcast.initialize();
    } catch (error, stack) {
      coreLog.warning('Could not initialise the bonsoir broadcast.', error, stack);
      _lastError = 'advertise: $error';
      return _AdvertiseResult.failed;
    }

    final outcome = Completer<_AdvertiseResult>();
    StreamSubscription<BonsoirBroadcastEvent>? subscription;
    subscription = broadcast.eventStream?.listen(
      (event) {
        switch (event) {
          case BonsoirBroadcastNameAlreadyExistsEvent():
            // Deliberately falls through: RFC 6763 auto-renames a conflicting
            // instance name and then reports it started, and a rename is normal
            // (two Macs both called "iPhone") rather than an error.
            _nameConflicts++;
            coreLog.info('Name conflict on "$name"; mDNS registered us as '
                '"${event.service.name}".');
          case BonsoirBroadcastStartedEvent():
            if (!outcome.isCompleted) outcome.complete(_AdvertiseResult.started);
          case BonsoirBroadcastStoppedEvent():
            // Stopped before it ever started: treat as a failure so the caller
            // gets its one retry.
            if (!outcome.isCompleted) outcome.complete(_AdvertiseResult.failed);
          default:
            break;
        }
      },
      onError: (Object error, StackTrace stack) {
        // The native side reports registration failures by pushing a FlutterError
        // into the event channel, so this - not a catch around start() - is where
        // a rejected service name or a denied permission actually shows up.
        _lastError = 'advertise: $error';
        coreLog.warning('bonsoir broadcast reported an error.', error, stack);
        if (!outcome.isCompleted) outcome.complete(_AdvertiseResult.failed);
      },
    );
    if (subscription == null) {
      _lastError = 'advertise: bonsoir produced no event stream';
      return _AdvertiseResult.failed;
    }

    try {
      await broadcast.start();
    } catch (error, stack) {
      coreLog.warning('Could not start the bonsoir broadcast.', error, stack);
      _lastError = 'advertise: $error';
      await subscription.cancel();
      await _tossBroadcast(broadcast);
      return _AdvertiseResult.failed;
    }

    _AdvertiseResult result;
    try {
      result = await outcome.future.timeout(kStartupTimeout);
    } on TimeoutException {
      // Silence is the documented symptom of a denied local-network permission
      // on macOS, so this must not be reported as success.
      _lastError ??= 'advertise: no confirmation within ${kStartupTimeout.inSeconds}s';
      result = _AdvertiseResult.unconfirmed;
    }

    if (result == _AdvertiseResult.failed) {
      await subscription.cancel();
      await _tossBroadcast(broadcast);
      return result;
    }

    _broadcast = broadcast;
    _broadcastSub = subscription;
    _registeredPort = port;
    return result;
  }

  /// The TXT attributes for our own service.
  ///
  /// Starts from [PeerInfo.toTxt] so the wire format has exactly one definition,
  /// then overrides the fields where the live value beats the snapshot:
  ///   * the port, because the transport may have bound an ephemeral one after
  ///     this [PeerInfo] was built;
  ///   * the name and id, because we are the one publishing them and can fix up
  ///     our own string rather than merely defending against it.
  Map<String, String> _advertisedAttributes(int port) {
    final self = _self;
    if (self == null) return const <String, String>{};
    final deviceId = sanitizeDeviceId(self.deviceId);
    if (deviceId.isEmpty) {
      // Self-inflicted outage: peers drop any record with no id (see
      // [parseResolvedService]), so advertising an empty one makes this device
      // invisible rather than merely unidentified.
      coreLog.warning('Our own device id sanitises to nothing; peers will not '
          'be able to identify us.');
    }
    return <String, String>{
      ...self.toTxt(),
      TxtKey.port: '$port',
      TxtKey.deviceName: sanitizeDeviceName(self.deviceName),
      TxtKey.deviceId: deviceId,
      TxtKey.osVersion: sanitizeShortVersion(self.osVersion),
      TxtKey.appVersion: sanitizeShortVersion(self.appVersion),
    };
  }

  // -------------------------------------------------------------------------
  // Browsing
  // -------------------------------------------------------------------------

  Future<void> _startDiscovery() async {
    _browse = _BrowseState.initialising;
    final BonsoirDiscovery discovery;
    try {
      discovery = BonsoirDiscovery(type: kServiceType, printLogs: false);
      await discovery.initialize();
    } catch (error, stack) {
      coreLog.warning('Could not initialise bonsoir discovery.', error, stack);
      _browse = _BrowseState.failed;
      _fail('mDNS browsing could not start: $error');
      return;
    }

    final stream = discovery.eventStream;
    if (stream == null) {
      _browse = _BrowseState.failed;
      _fail('mDNS browsing produced no event stream.');
      return;
    }

    _discovery = discovery;
    _discoverySub = stream.listen(
      _onDiscoveryEvent,
      onError: (Object error, StackTrace stack) {
        _lastError = 'browse: $error';
        coreLog.warning('bonsoir discovery reported an error.', error, stack);
        _browse = _BrowseState.failed;
        _failure ??= 'mDNS browsing stopped: $error';
      },
    );
    try {
      await discovery.start();
    } catch (error, stack) {
      coreLog.warning('Could not start bonsoir discovery.', error, stack);
      _browse = _BrowseState.failed;
      _fail('mDNS browsing could not start: $error');
      await _dropDiscovery();
      return;
    }

    // Only now: a timer firing against a browser that failed to start would just
    // produce noise.
    _refreshTimer ??= Timer.periodic(kRefreshInterval, (Timer _) => _refreshAll());
  }

  void _onDiscoveryEvent(BonsoirDiscoveryEvent event) {
    if (_disposed) return;
    _lastEvent = event.id ?? event.runtimeType.toString();
    _lastEventAt = DateTime.now();
    switch (event) {
      case BonsoirDiscoveryStartedEvent():
        // Darwin emits this from the browser's `.ready` state: the local network
        // stack accepted our browse request.
        _browse = _BrowseState.browsing;
        coreLog.fine('mDNS browser ready.');
      case BonsoirDiscoveryServiceFoundEvent():
        _handleFound(event.service);
      case BonsoirDiscoveryServiceResolvedEvent():
        _handleResolved(event.service);
      case BonsoirDiscoveryServiceUpdatedEvent():
        // A TXT change (new port, new capabilities). Re-emit so the UI refreshes.
        _handleResolved(event.service);
      case BonsoirDiscoveryServiceResolveFailedEvent():
        // Common and usually benign: the peer went away between the browse and
        // the resolve, or its SRV record pointed nowhere.
        _resolveFailures++;
        coreLog.fine('A discovered service could not be resolved.');
      case BonsoirDiscoveryServiceLostEvent():
        // Logged only, deliberately. The UI expires peers by age, and
        // DiscoveryService has no "gone" event to emit - inventing one would let
        // anyone on the LAN evict a real peer from somebody's list simply by
        // broadcasting its service and then withdrawing it.
        _lostEvents++;
        _liveServices.remove(event.service.name);
        coreLog.fine('Lost ${event.service.name}');
      case BonsoirDiscoveryStoppedEvent():
        _browse = _BrowseState.stopped;
      case BonsoirDiscoveryUnknownEvent():
        coreLog.fine('Ignoring unknown bonsoir event ${event.id}.');
    }
  }

  void _handleFound(BonsoirService service) {
    _foundEvents++;
    _rememberName(service.name);

    final selfId = sanitizeDeviceId(_self?.deviceId ?? '');
    final advertisedId = sanitizeDeviceId(service.attributes[TxtKey.deviceId] ?? '');
    if (advertisedId.isNotEmpty && selfId.isNotEmpty && advertisedId == selfId) {
      // Our own advertisement. Checked here as well as in
      // [parseResolvedService] so we never spend a native resolve on ourselves.
      _selfFiltered++;
      return;
    }
    // Note what is deliberately *not* done here: dropping a service whose
    // attributes are still empty. Whether the TXT record is available at `found`
    // time is a platform difference - bonsoir_darwin browses with
    // `bonjourWithTXTRecord` so `found` already carries them, while
    // bonsoir_android emits `discoveryServiceFound` with an empty map and only
    // fills it in afterwards via `discoveryServiceUpdated`. Refusing to resolve
    // an attribute-less `found` would therefore break Android completely, and the
    // record is re-checked in [parseResolvedService] once it actually arrives.

    final resolver = _discovery?.serviceResolver;
    if (resolver == null) return;
    _resolveRequests++;
    unawaited(_resolve(service, resolver));
  }

  void _handleResolved(BonsoirService service) {
    final self = _self;
    if (_disposed || self == null) return;
    _resolvedEvents++;
    _rememberLive(service);

    // Only numeric literals are accepted. Bonsoir also exposes an mDNS
    // `hostname`, but PeerAddress's own doc is right that resolving a `.local`
    // name needs working multicast - precisely the thing that may be broken -
    // so a name would be a worse answer than no peer at all.
    final addresses = <InternetAddress>[
      for (final raw in service.hostAddresses) ?InternetAddress.tryParse(raw),
    ];

    // Classify the rejection first so [diagnostics] can explain itself; the
    // parsing below re-checks everything anyway.
    final advertisedId = sanitizeDeviceId(service.attributes[TxtKey.deviceId] ?? '');
    if (advertisedId.isEmpty) {
      _rejectedNoId++;
    } else if (advertisedId == sanitizeDeviceId(self.deviceId)) {
      _selfFiltered++;
    } else if (selectHostAddress(addresses) == null) {
      _rejectedNoAddress++;
      coreLog.info('Peer $advertisedId resolved with no dialable address '
          '(${service.hostAddresses.join(', ')}).');
    }

    final peer = parseResolvedService(
      service.attributes,
      addresses,
      self.deviceId,
      servicePort: service.port,
    );
    if (peer == null) return;

    _peersEmitted++;
    _emit(peer);
    coreLog.fine('Peer ${peer.info.deviceName} (${peer.deviceId}) '
        'version ${peer.info.protocolVersion} at ${peer.address}');
  }

  /// Ask the platform to (re-)resolve [service].
  ///
  /// Deliberately calls [ServiceResolver.resolveService] rather than the
  /// `service.resolve(resolver)` extension: the extension short-circuits when
  /// `hostAddresses` is already populated, which is exactly the case for the
  /// periodic refresh, so using it would turn the refresh into a no-op.
  Future<void> _resolve(BonsoirService service, ServiceResolver resolver) async {
    try {
      await resolver.resolveService(service);
    } catch (error) {
      // bonsoir reports resolve failures as events; an exception here is
      // platform-specific noise and must not take the event stream down.
      _resolveFailures++;
      coreLog.fine('resolveService("${service.name}") threw: $error');
    }
  }

  /// Re-resolve everything we currently know about.
  ///
  /// The point is liveness, not discovery: a successful resolve re-emits the peer
  /// with a fresh `resolvedAt`, so the UI's age-based expiry keeps a peer that is
  /// still answering and quietly ages out one that is not. Skipped entirely when
  /// nobody is listening, so a backgrounded app does not keep the network busy.
  void _refreshAll() {
    if (_disposed || !_running) return;
    if (!_peers.hasListener) return;
    final resolver = _discovery?.serviceResolver;
    if (resolver == null || _liveServices.isEmpty) return;
    coreLog.finer('Re-resolving ${_liveServices.length} known peer(s).');
    for (final service in _liveServices.values) {
      _resolveRequests++;
      unawaited(_resolve(service, resolver));
    }
  }

  // -------------------------------------------------------------------------
  // Bookkeeping
  // -------------------------------------------------------------------------

  void _emit(DiscoveredPeer peer) {
    // A native callback can still be in flight when dispose() runs; adding to a
    // closed controller throws, and losing a peer record is not worth an
    // unhandled exception.
    if (_disposed || _peers.isClosed) return;
    _peers.add(peer);
  }

  void _rememberName(String name) {
    if (name.isEmpty) return;
    _seenNames.add(name);
    if (_seenNames.length == 1) _servicesSeen++;
    while (_seenNames.length > kMaxRememberedNames) {
      _seenNames.remove(_seenNames.first);
    }
  }

  void _rememberLive(BonsoirService service) {
    final name = service.name;
    if (name.isEmpty) return;
    _liveServices.remove(name);
    _liveServices[name] = service;
    // Bounded: a hostile LAN can keep announcing new services forever.
    while (_liveServices.length > kMaxTrackedServices) {
      _liveServices.remove(_liveServices.keys.first);
    }
  }

  void _fail(String reason) {
    _failure = reason;
    coreLog.warning('mDNS discovery unavailable: $reason');
  }

  Future<void> _dropBroadcast() async {
    final broadcast = _broadcast;
    _broadcast = null;
    final subscription = _broadcastSub;
    _broadcastSub = null;
    _registeredPort = null;
    await subscription?.cancel();
    if (broadcast == null) return;
    await _tossBroadcast(broadcast);
  }

  Future<void> _tossBroadcast(BonsoirBroadcast broadcast) async {
    try {
      await broadcast.stop();
    } catch (error) {
      coreLog.fine('Ignoring an error while stopping the broadcast: $error');
    }
  }

  Future<void> _dropDiscovery() async {
    final discovery = _discovery;
    _discovery = null;
    final subscription = _discoverySub;
    _discoverySub = null;
    await subscription?.cancel();
    if (discovery == null) return;
    try {
      await discovery.stop();
    } catch (error) {
      coreLog.fine('Ignoring an error while stopping discovery: $error');
    }
  }

  /// A plain-language explanation for the "nothing is happening" case.
  String? _hint() {
    if (!_running) return null;
    if (_browse != _BrowseState.browsing) {
      return 'The mDNS browser has not reported a ready state yet.';
    }
    final started = _startedAt;
    if (_servicesSeen == 0 &&
        started != null &&
        DateTime.now().difference(started) > kSilentHintDelay) {
      return 'Browsing is running but nothing has answered. Check that the other '
          'device is on the same subnet and that local-network access is '
          'granted: macOS/iOS need NSLocalNetworkUsageDescription (and '
          'NSBonjourServices must list $kServiceType) in Info.plist, Android 16+ '
          'needs ACCESS_LOCAL_NETWORK.';
    }
    return null;
  }

  static String _ago(DateTime? when) {
    if (when == null) return '-';
    return '${DateTime.now().difference(when).inSeconds}s ago';
  }
}

/// Outcome of one attempt to register our service with the platform.
enum _AdvertiseResult {
  /// The platform confirmed the registration.
  started,

  /// No confirmation arrived within [kStartupTimeout]. The registration may still
  /// be live; treating silence as failure would be worse than treating it as
  /// unknown.
  unconfirmed,

  /// The platform rejected it. The caller may retry once with an ASCII name.
  failed,
}