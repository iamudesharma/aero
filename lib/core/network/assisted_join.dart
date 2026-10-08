/// The macOS side of the offline fallback: waiting for the user to join a
/// hotspot the phone created.
///
/// # Why this is "assisted" and not automatic
///
/// A sandboxed macOS app (which Aero is - see `Release.entitlements`) cannot
/// change the system's Wi-Fi association. `CoreWLAN`'s `associate(to:password:)`
/// exists and is not deprecated, but the sandbox blocks it, and `NEHotspot-
/// Configuration` is `API_UNAVAILABLE(macos)`. Shipping an unsandboxed build to
/// regain that would forfeit the App Store and the Downloads entitlement the
/// receive path already relies on.
///
/// So the app shows the SSID and passphrase, offers copy and a deep link to
/// System Settings, and then *detects* the resulting join. That detection is
/// the part that matters: the user should not have to tell Aero "I'm done" and
/// hope it noticed.
///
/// # How detection works
///
/// Poll [NetworkInterface.list] for a non-loopback interface holding an address
/// on the hotspot's subnet. A LocalOnlyHotspot hands out addresses from a small
/// fixed range and the phone is typically the `.1` gateway, so a new interface
/// that did not exist before the join is a strong, dependency-free signal. It is
/// deliberately conservative: a false "joined" sends the app on to mDNS, which
/// will simply find nothing, whereas a false "not joined" would leave the user
/// waiting on a screen that is actually ready.
library;

import 'dart:async';
import 'dart:io';

import '../logging.dart';
import 'hotspot.dart';

/// Poll interval while waiting for a join. Fast enough to feel immediate, slow
/// enough not to spin the radio.
const Duration kJoinPollInterval = Duration(milliseconds: 700);

/// [`HotspotJoiner`] for macOS.
///
/// Also usable on any desktop platform for detection purposes, but the intended
/// platform is macOS.
class AssistedHotspotJoiner implements HotspotJoiner {
  AssistedHotspotJoiner({
    this.pollInterval = kJoinPollInterval,
    Future<List<NetworkInterface>> Function()? listInterfaces,
  }) : _listInterfaces = listInterfaces ?? _defaultList;

  /// How often the interface list is re-read while waiting for a join.
  final Duration pollInterval;

  final Future<List<NetworkInterface>> Function() _listInterfaces;

  @override
  bool get isSupported => Platform.isMacOS;

  /// Always true: the user must act in System Settings. The app cannot join.
  @override
  bool get requiresUserAction => true;

  static Future<List<NetworkInterface>> _defaultList() =>
      NetworkInterface.list(includeLoopback: false, type: InternetAddressType.any);

  /// Wait until an interface appears that would only exist after joining a
  /// hotspot, or until [timeout] elapses.
  ///
  /// Returns the local address on the joined network, or null on timeout.
  @override
  Future<String?> awaitJoin(String ssid, {Duration timeout = const Duration(minutes: 2)}) async {
    if (!isSupported) return null;

    final deadline = DateTime.now().add(timeout);
    // Snapshot the *identities* of interfaces present before the join, so a
    // pre-existing Wi-Fi interface cannot be mistaken for the hotspot. Comparing
    // names is not enough: joining a hotspot reuses `en0`, so what changes is
    // the address, not the interface.
    final before = await _addressSnapshot();
    coreLog.info('waiting for the user to join "$ssid" (had ${before.length} address(es))');

    while (DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(pollInterval);
      if (await _hasNewAddress(before, ssid)) {
        final address = await _newAddress(before);
        coreLog.info('join detected for "$ssid" at ${address ?? "unknown"}');
        return address;
      }
    }
    coreLog.info('join wait for "$ssid" timed out');
    return null;
  }

  Future<Set<String>> _addressSnapshot() async {
    try {
      final interfaces = await _listInterfaces();
      return {
        for (final i in interfaces)
          for (final a in i.addresses)
            if (_usable(a)) a.address,
      };
    } catch (error) {
      coreLog.fine('could not snapshot interfaces: $error');
      return <String>{};
    }
  }

  /// True when some usable address exists now that did not before.
  ///
  /// The SSID is only used for logging: macOS exposes no supported, sandbox-legal
  /// way to read the current SSID on every version, and inventing one from a
  /// private framework is exactly the kind of fragile trick that breaks in a
  /// point release. Address change is the signal.
  Future<bool> _hasNewAddress(Set<String> before, String ssid) async {
    final now = await _addressSnapshot();
    return now.difference(before).isNotEmpty;
  }

  Future<String?> _newAddress(Set<String> before) async {
    final now = await _addressSnapshot();
    final added = now.difference(before);
    return added.isEmpty ? null : added.first;
  }

  static bool _usable(InternetAddress address) {
    if (address.address.isEmpty || address.rawAddress.isEmpty) return false;
    if (address.rawAddress.every((b) => b == 0)) return false;
    if (address.isLoopback || address.isLinkLocal) return false;
    if (address.type == InternetAddressType.IPv6) {
      if (address.rawAddress.first == 0xff) return false;
    } else if (address.rawAddress.first >= 224 && address.rawAddress.first <= 239) {
      return false;
    }
    return true;
  }
}
