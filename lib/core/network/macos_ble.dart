/// The macOS side of BLE rendezvous: scanning (central role).
///
/// Talks to `aero/ble` in `AppDelegate.swift`, which wraps `CBCentralManager`.
/// A sandboxed Mac app is a reliable BLE **central**, so this is the only
/// direction implemented on Apple platforms - the two roles do not need to be
/// symmetric, and pretending otherwise would mean writing a peripheral that
/// cannot advertise reliably under the sandbox.
///
/// Note the TCC prompt: the first scan triggers the system Bluetooth permission
/// dialog, and a denied prompt produces a scan that simply never reports a
/// device - indistinguishable from an empty room without the reason this class
/// surfaces.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

import '../logging.dart';
import 'ble_rendezvous.dart';

/// Channel name, shared with the Swift side.
const String kBleChannelMac = 'aero/ble';

/// Default scan window.
const Duration kDefaultBleScanTimeout = Duration(seconds: 25);

/// [`BleScanner`] backed by `CBCentralManager`.
class MacBleScanner implements BleScanner {
  MacBleScanner({
    this.channel = const MethodChannel(kBleChannelMac),
    this.isSupportedOverride,
  });

  /// Exposed so tests can substitute a fake channel.
  final MethodChannel channel;

  /// Test seam: the platform check is overridable so unit tests can exercise
  /// the channel without a real radio.
  final bool? isSupportedOverride;

  @override
  bool get isSupported => isSupportedOverride ?? Platform.isMacOS;

  @override
  String? get unsupportedReason =>
      isSupported ? null : 'Only macOS scans for an Aero BLE rendezvous.';

  @override
  Future<BleRendezvous?> scanOnce({
    Duration timeout = kDefaultBleScanTimeout,
  }) async {
    if (!isSupported) {
      throw BleException(
        BleFailure.unsupported,
        unsupportedReason ?? 'This device cannot scan over Bluetooth.',
      );
    }

    Map<Object?, Object?>? raw;
    try {
      
      raw = await channel.invokeMethod<Map<Object?, Object?>>('scanForRendezvous', {
        'timeoutMs': timeout.inMilliseconds,
      });
    } on PlatformException catch (error) {
      throw BleException(
        BleFailure.fromName(error.code),
        error.message ?? '',
        error,
      );
    } on MissingPluginException catch (error) {
      throw BleException(
        BleFailure.channelUnavailable,
        'the $kBleChannelMac channel is not registered',
        error,
      );
    } finally {
      
    }

    if (raw == null) {
      // Null means the scan window closed with nothing found. That is a normal
      // outcome (the other device may not be advertising yet), not an error.
      coreLog.info('BLE rendezvous scan found nothing within '
          '${timeout.inSeconds}s');
      return null;
    }

    final rendezvous = BleRendezvous.tryFromJson(raw);
    if (rendezvous == null) {
      coreLog.warning('BLE rendezvous scan returned an unusable payload');
      return null;
    }
    coreLog.info('BLE rendezvous found: $rendezvous');
    return rendezvous;
  }

  @override
  Future<void> stop() async {
    
    try {
      await channel.invokeMethod<void>('stopScan');
    } on PlatformException catch (error) {
      coreLog.warning('stopScan failed', error);
    } on MissingPluginException {
      // Nothing to stop on a VM or unregistered platform.
    }
  }

  /// Ask the OS whether scanning is possible, and why not if it is not.
  Future<BleCapability> capability() async {
    if (!isSupported) {
      return const BleCapability(
        supported: false,
        reason: 'Not a macOS device.',
      );
    }
    try {
      final raw = await channel.invokeMethod<Map<Object?, Object?>>('bleCapability');
      if (raw == null) {
        return const BleCapability(supported: false, reason: 'No capability reported.');
      }
      return BleCapability(
        supported: raw['supported'] as bool? ?? false,
        reason: (raw['reason'] as String?) ?? '',
        permission: (raw['permission'] as String?) ?? '',
      );
    } on PlatformException catch (error) {
      return BleCapability(supported: false, reason: error.message ?? error.code);
    } on MissingPluginException {
      return const BleCapability(
        supported: false,
        reason: 'The native BLE channel is not available.',
      );
    }
  }
}
