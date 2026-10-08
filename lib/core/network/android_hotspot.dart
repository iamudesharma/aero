/// The Android side of the offline fallback, over a `MethodChannel`.
///
/// Talks to `MainActivity`'s `aero/direct` channel, which wraps
/// `WifiManager.startLocalOnlyHotspot()`. All protocol knowledge stays in Dart:
/// the native side starts and stops the AP and reports plain strings, while the
/// decision to do so, and everything that follows, lives here and above.
///
/// # Why a hand-rolled channel rather than a pub plugin
///
/// The maintained Flutter Wi-Fi packages wrap `WifiNetworkSpecifier` (joining)
/// or ordinary tethering, not `startLocalOnlyHotspot`, and the ones that do are
/// either unmaintained or reach past the callback API. The native surface we
/// need is small - start, stop, report capability - so owning it is less risk
/// than depending on a thin wrapper we would have to patch anyway.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

import '../logging.dart';
import 'hotspot.dart';

/// Channel name. Kept here so the Kotlin side and this file cannot drift.
const String kHotspotChannel = 'aero/direct';

/// How long to wait for the OS to hand back access-point details.
///
/// `startLocalOnlyHotspot` reports success through an asynchronous callback and
/// can genuinely take seconds on a busy radio, so this is generous. Failing
/// slowly is better than reporting a hotspot that is not up yet: the user would
/// be sent to a network that does not exist.
const Duration kHotspotStartTimeout = Duration(seconds: 20);

/// [`HotspotProvisioner`] backed by the Android `WifiManager`.
class AndroidHotspotProvisioner implements HotspotProvisioner {
  AndroidHotspotProvisioner({
    MethodChannel channel = const MethodChannel(kHotspotChannel),
    Duration startTimeout = kHotspotStartTimeout,
    bool? isSupportedOverride,
  })  : // A named `channel` reads far better than `_channel:` at the call site, so
        // the lint is suppressed rather than the ergonomics given up.
        // ignore: prefer_initializing_formals
        _channel = channel,
        // ignore: prefer_initializing_formals
        _startTimeout = startTimeout,
        // ignore: prefer_initializing_formals
        _isSupportedOverride = isSupportedOverride;

  final MethodChannel _channel;
  final Duration _startTimeout;

  /// Test seam: `Platform.isAndroid` is false in the unit-test VM, so the
  /// platform check is overridable rather than hardcoded. Production never
  /// passes this.
  final bool? _isSupportedOverride;

  HotspotSession? _session;
  Future<HotspotSession>? _inFlight;

  @override
  bool get isSupported => _isSupportedOverride ?? Platform.isAndroid;

  @override
  String? get unsupportedReason =>
      isSupported ? null : 'This device cannot create a hotspot.';

  @override
  HotspotSession? get session => _session;

  /// Start a hotspot, coalescing concurrent callers.
  ///
  /// Two taps on "Direct transfer" must not race into two `startLocalOnlyHotspot`
  /// calls: the OS would either refuse the second or the two callbacks would
  /// fight over `_session`. Sharing the in-flight future makes the call
  /// idempotent, which is the contract [HotspotProvisioner.start] promises.
  @override
  Future<HotspotSession> start() {
    final existing = _session;
    if (existing != null) return Future<HotspotSession>.value(existing);
    return _inFlight ??= _startOnce().whenComplete(() => _inFlight = null);
  }

  Future<HotspotSession> _startOnce() async {
    if (!isSupported) {
      throw HotspotProvisionException(
        HotspotFailure.unsupported,
        unsupportedReason ?? 'This device cannot create a hotspot.',
      );
    }

    Map<Object?, Object?>? raw;
    try {
      raw = await _channel
          .invokeMethod<Map<Object?, Object?>>('startHotspot')
          .timeout(
            _startTimeout,
            onTimeout: () => throw HotspotProvisionException(
              HotspotFailure.timeout,
              'the hotspot did not come up within ${_startTimeout.inSeconds}s',
            ),
          );
    } on PlatformException catch (error) {
      throw _translate(error);
    } on MissingPluginException catch (error) {
      throw HotspotProvisionException(
        HotspotFailure.channelUnavailable,
        'the $kHotspotChannel channel is not registered',
        error,
      );
    }

    final session = HotspotSession.tryFromJson(raw);
    if (session == null) {
      // The native side reported success but the payload is unusable. Sending
      // the user to a network with no name would be worse than failing.
      throw HotspotProvisionException(
        HotspotFailure.malformed,
        'the native hotspot reported no usable ssid',
      );
    }

    _session = session;
    coreLog.info('hotspot started: ${session.redacted}');
    return session;
  }

  /// Stop the hotspot and forget the session.
  ///
  /// Deliberately tolerates a stop that fails: the reservation may already be
  /// gone (the OS reclaims it when the app is backgrounded or killed), and
  /// throwing here would leave `_session` set to credentials for a network that
  /// no longer exists.
  @override
  Future<void> stop() async {
    final had = _session != null;
    _session = null;
    try {
      await _channel.invokeMethod<void>('stopHotspot');
    } on PlatformException catch (error) {
      coreLog.warning('stopHotspot failed', error);
    } on MissingPluginException {
      // Nothing to stop on a VM or an unregistered platform.
    }
    if (had) coreLog.info('hotspot stopped');
  }

  /// Current capability, straight from the OS.
  ///
  /// Separate from [isSupported] because "Android" and "this Android device"
  /// are different questions: tethering can be disabled by carrier policy, and
  /// some ROMs remove the feature. The result is cached by nothing - callers
  /// that need it are about to start a hotspot anyway.
  Future<HotspotCapability> capability() async {
    if (!isSupported) {
      return const HotspotCapability(
        supported: false,
        reason: 'Not an Android device.',
      );
    }
    try {
      final raw = await _channel.invokeMethod<Map<Object?, Object?>>('capability');
      if (raw == null) {
        return const HotspotCapability(supported: false, reason: 'No capability reported.');
      }
      return HotspotCapability(
        supported: raw['supported'] as bool? ?? false,
        reason: (raw['reason'] as String?) ?? '',
        permission: (raw['permission'] as String?) ?? '',
      );
    } on PlatformException catch (error) {
      return HotspotCapability(supported: false, reason: error.message ?? error.code);
    } on MissingPluginException {
      return const HotspotCapability(
        supported: false,
        reason: 'The native hotspot channel is not available.',
      );
    }
  }

  /// Ask the OS for the hotspot permission.
  ///
  /// Exposed so the UI can preflight and explain *before* a start attempt, which
  /// is friendlier than starting and catching `permission_denied`. Returns true
  /// when we already hold it or the user grants it.
  Future<bool> requestPermission() async {
    if (!isSupported) return false;
    try {
      return await _channel.invokeMethod<bool>('requestPermission') ?? false;
    } on PlatformException catch (error) {
      coreLog.warning('requestPermission failed: ${error.message}');
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// Map a native `PlatformException` onto a typed [HotspotFailure].
  ///
  /// The Kotlin side sets `code` to one of [HotspotFailure]'s ids, so this is a
  /// lookup rather than message-sniffing - which is the whole reason the native
  /// side is told to use those exact strings.
  static HotspotProvisionException _translate(PlatformException error) {
    final failure = HotspotFailure.fromName(error.code);
    return HotspotProvisionException(failure, error.message ?? '', error);
  }
}

/// Whether the device can host a hotspot, and if not, why.
class HotspotCapability {
  const HotspotCapability({
    required this.supported,
    this.reason = '',
    this.permission = '',
  });

  final bool supported;

  /// Human-readable explanation when [supported] is false.
  final String reason;

  /// The runtime permission this platform requires, so the UI can name it.
  final String permission;

  Map<String, dynamic> toJson() => {
        'supported': supported,
        'reason': reason,
        'permission': permission,
      };

  @override
  String toString() =>
      'HotspotCapability(supported=$supported${reason.isEmpty ? '' : ', $reason'})';
}
