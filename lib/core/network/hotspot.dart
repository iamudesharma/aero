/// The offline fallback that turns a phone into the network.
///
/// # The problem this solves
///
/// Aero's normal path needs both devices on one subnet. When they are not - the
/// Mac is on Ethernet, the phone is on cellular, or there is no router at all -
/// there is no link for mDNS to advertise across. Android can fix this by
/// creating a **LocalOnlyHotspot**: a real access point with no internet, which
/// the Mac then joins as an ordinary Wi-Fi client. Once that happens a shared
/// subnet exists again and *every other layer runs unchanged* - mDNS, TLS, the
/// SAS, the file transfer. This file only has to stand up the link.
///
/// # What this layer is NOT
///
/// It is not authentication. The SSID and passphrase below are handed to the
/// user to type or copy, which means they are public and a hostile hotspot is
/// entirely possible. That is fine: the six-digit SAS derived from the two TLS
/// certificate fingerprints is still the thing that proves the peers are who
/// they say, and it still fails against a man in the middle *even on a
/// malicious hotspot*. Treat the hotspot as a dumb, untrusted cable.
library;

import '../logging.dart';

/// Why a hotspot could not be started, or why joining one failed.
///
/// A typed reason rather than a string because the UI response differs: some of
/// these are "user must grant a permission", some are "try again", and some are
/// "this device cannot do it at all". String-matching an exception message is
/// how those three get conflated.
enum HotspotFailure {
  /// This platform has no hotspot provisioner (macOS *creates* nothing; it
  /// joins). Not an error so much as "this side does not do that".
  unsupported('unsupported'),

  /// The runtime permission (`NEARBY_WIFI_DEVICES` on API 33+, or location on
  /// older releases) was denied. The user can fix this.
  permissionDenied('permission_denied'),

  /// The OS refused because tethering is disabled by policy - common on
  /// enterprise-managed devices and some carrier builds. Not user-fixable.
  tetheringDisallowed('tethering_disallowed'),

  /// No free channel / radio busy. Usually transient.
  noChannel('no_channel'),

  /// The radio is in a mode that cannot host an AP (e.g. already hosting).
  incompatibleMode('incompatible_mode'),

  /// The OS reported a generic failure.
  generic('generic'),

  /// A start was requested while one was already running. Idempotent callers
  /// get the existing session instead, so this is only surfaced when the
  /// existing session is in an unknown state.
  alreadyRunning('already_running'),

  /// The platform channel is not wired up (a unit-test VM, or a platform we
  /// have not implemented). Distinct from [unsupported]: the *capability* may
  /// exist, we just cannot reach it.
  channelUnavailable('channel_unavailable'),

  /// Timed out waiting for the OS to produce access-point details.
  timeout('timeout'),

  /// The hotspot started but reported no usable SSID/address, so it cannot be
  /// joined. Treating this as success would send the user to a network that
  /// does not exist.
  malformed('malformed');

  const HotspotFailure(this.id);

  /// Stable identifier for the wire and for logs.
  final String id;

  static HotspotFailure fromName(String? name) {
    for (final f in HotspotFailure.values) {
      if (f.id == name) return f;
    }
    return HotspotFailure.generic;
  }

  @override
  String toString() => id;
}

/// A started hotspot: everything the other device needs to join it.
///
/// Immutable, because the credentials are snapshotted when the AP comes up and
/// must not drift: the Mac may have already typed them.
class HotspotSession {
  const HotspotSession({
    required this.ssid,
    required this.psk,
    required this.gatewayIp,
    this.security = HotspotSecurity.wpa2,
    this.requiresUserJoin = false,
  });

  /// Network name to join.
  final String ssid;

  /// Passphrase. Empty for an open network, which LocalOnlyHotspot never
  /// produces but a manual/QR tier might.
  final String psk;

  /// Address of the hotspot itself, i.e. the phone. This is the one address the
  /// Mac can always reach even if mDNS fails, so it is also the endpoint a
  /// manual/QR fallback would hand over. Empty when unknown.
  final String gatewayIp;

  final HotspotSecurity security;

  /// True when the far side must be told the credentials and join manually
  /// (the macOS assisted-join flow). False when the OS joined automatically.
  final bool requiresUserJoin;

  /// Whether the hotspot is open (no passphrase).
  bool get isOpen => psk.isEmpty;

  /// `ssid` plus a masked passphrase, safe to log.
  ///
  /// The SSID is not a secret - it is broadcast - so it appears in full. The
  /// passphrase is masked even in logs: a log file outlives the session it was
  /// written for, and someone reading a bug report should not be handed the
  /// credentials to a network their colleague may be standing up right now.
  String get redacted => 'HotspotSession($ssid, psk=${isOpen ? '<open>' : '***'}, '
      'gw=${gatewayIp.isEmpty ? 'unknown' : gatewayIp})';

  Map<String, dynamic> toJson() => {
        'ssid': ssid,
        'psk': psk,
        'gatewayIp': gatewayIp,
        'security': security.name,
        'requiresUserJoin': requiresUserJoin,
      };

  static HotspotSession? tryFromJson(Object? raw) {
    if (raw is! Map) return null;
    final map = raw.cast<Object?, Object?>();
    final ssid = (map['ssid'] as String?)?.trim() ?? '';
    if (ssid.isEmpty) return null;
    return HotspotSession(
      ssid: ssid,
      psk: (map['psk'] as String?) ?? '',
      gatewayIp: (map['gatewayIp'] as String?)?.trim() ?? '',
      security: switch (map['security'] as String?) {
        'open' => HotspotSecurity.open,
        _ => HotspotSecurity.wpa2,
      },
      requiresUserJoin: map['requiresUserJoin'] as bool? ?? false,
    );
  }

  @override
  String toString() => redacted;
}

/// Security mode of the created hotspot.
enum HotspotSecurity { open, wpa2 }

/// A platform-specific inability to create a hotspot, carrying a typed reason.
class HotspotProvisionException implements Exception {
  HotspotProvisionException(this.failure, [this.message = '', this.cause]);

  final HotspotFailure failure;
  final String message;
  final Object? cause;

  @override
  String toString() =>
      'HotspotProvisionException(${failure.id}${message.isEmpty ? '' : ': $message'})';
}

/// Creates a hotspot this device will host, so another device can join it.
///
/// One implementation per platform that can *host*: Android. macOS implements
/// nothing here - it joins, and that lives behind [HotspotJoiner].
abstract class HotspotProvisioner {
  /// Whether this platform can host at all, before any permission check.
  ///
  /// Synchronous and cheap so the UI can decide whether to even offer the
  /// "Direct transfer" action. A `true` here is not a promise that starting will
  /// succeed - permissions and tethering policy can still refuse - only that the
  /// capability exists.
  bool get isSupported;

  /// A short sentence explaining why hosting is unavailable, or null.
  String? get unsupportedReason;

  /// Start a hotspot and return its details.
  ///
  /// Starting is idempotent: a second call while one is running returns the
  /// existing session rather than failing, because the UI may re-enter this
  /// after a rebuild.
  Future<HotspotSession> start();

  /// Stop the hotspot. Safe to call when none is running.
  Future<void> stop();

  /// The currently running session, if any. Synchronous so the UI can render
  /// the credentials without an await.
  HotspotSession? get session;
}

/// Joins this device to a hotspot created by a peer.
///
/// Only macOS needs this in Phase 1, and only as an *assisted* join: a sandboxed
/// Mac app cannot change the system's Wi-Fi association, so the app shows the
/// credentials and waits for the network to appear.
abstract class HotspotJoiner {
  /// Whether this platform can join at all.
  bool get isSupported;

  /// True when joining needs the user to act in System Settings rather than the
  /// app doing it. Always true on sandboxed macOS.
  bool get requiresUserAction;

  /// Watch for the device to join [ssid].
  ///
  /// Completes with the local address obtained on that network once the OS
  /// reports the join, or with null if the caller's timeout elapses first.
  /// Detection only - this must never try to *perform* the join on a platform
  /// that forbids it.
  Future<String?> awaitJoin(String ssid, {Duration timeout});
}

/// A [HotspotProvisioner] for platforms that cannot host.
///
/// Exists so the coordinator never needs a null check and a platform switch in
/// the same breath: "not supported" becomes a value, and the UI can render one
/// consistent message on every non-Android platform.
class UnsupportedHotspotProvisioner implements HotspotProvisioner {
  const UnsupportedHotspotProvisioner(this.unsupportedReason);

  @override
  final String? unsupportedReason;

  @override
  bool get isSupported => false;

  @override
  HotspotSession? get session => null;

  @override
  Future<HotspotSession> start() async {
    throw HotspotProvisionException(
      HotspotFailure.unsupported,
      unsupportedReason ?? 'This device cannot create a hotspot.',
    );
  }

  @override
  Future<void> stop() async {
    coreLog.fine('stop() on an unsupported hotspot provisioner is a no-op');
  }
}
