/// The Android side of BLE rendezvous: advertising (peripheral role).
///
/// Talks to the `aero/ble` channel in `MainActivity`, which wraps
/// `BluetoothLeAdvertiser` plus a small GATT server. The split matters:
///
///   * the **advertisement** carries only the fixed Aero service UUID plus a
///     short rendezvous id, because a legacy BLE advertisement is 31 bytes total
///     and cannot hold a URL, an SSID, and a passphrase;
///   * the **GATT characteristic** serves the full [`BleRendezvous`] payload once
///     a central connects.
///
/// This is the "advertise just enough to be discovered, then use GATT" pattern
/// CoreBluetooth and Android both expect; trying to cram everything into the
/// advertisement is the classic mistake that works on one OS and not the other.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import '../logging.dart';
import 'ble_rendezvous.dart';

/// Channel name, shared with the Kotlin side.
const String kBleChannel = 'aero/ble';

/// How long to wait for the OS to confirm advertising started.
const Duration kBleStartTimeout = Duration(seconds: 15);

/// [`BleAdvertiser`] backed by Android's `BluetoothLeAdvertiser` + GATT server.
class AndroidBleAdvertiser implements BleAdvertiser {
  AndroidBleAdvertiser({
    this.channel = const MethodChannel(kBleChannel),
    this.startTimeout = kBleStartTimeout,
    this.isSupportedOverride,
  });

  /// Exposed so tests can substitute a fake channel.
  final MethodChannel channel;

  /// How long to wait for the OS to confirm advertising started.
  final Duration startTimeout;

  /// Test seam: the platform check is overridable so unit tests can exercise
  /// the channel without a real radio.
  final bool? isSupportedOverride;

  bool _advertising = false;

  @override
  bool get isSupported => isSupportedOverride ?? Platform.isAndroid;

  @override
  String? get unsupportedReason =>
      isSupported ? null : 'Only Android advertises an Aero BLE rendezvous.';

  @override
  bool get isAdvertising => _advertising;

  @override
  Future<void> start({
    required String rendezvousId,
    required BleRendezvous payload,
  }) async {
    if (!isSupported) {
      throw BleException(
        BleFailure.unsupported,
        unsupportedReason ?? 'This device cannot advertise over Bluetooth.',
      );
    }

    // The payload is encoded here and sent as a string: the native side only
    // has to put bytes in a characteristic, and keeping the JSON shape in Dart
    // means there is one definition of the rendezvous format.
    final encoded = jsonEncode(payload.toJson());
    if (encoded.length > kMaxRendezvousBytes) {
      throw BleException(
        BleFailure.generic,
        'the rendezvous payload is ${encoded.length} bytes, over the cap',
      );
    }

    try {
      await channel.invokeMethod<void>('startAdvertising', {
        'rendezvousId': rendezvousId,
        'payload': encoded,
      }).timeout(
        startTimeout,
        onTimeout: () => throw BleException(
          BleFailure.timeout,
          'advertising did not start within ${startTimeout.inSeconds}s',
        ),
      );
    } on PlatformException catch (error) {
      throw _translate(error);
    } on MissingPluginException catch (error) {
      throw BleException(
        BleFailure.channelUnavailable,
        'the $kBleChannel channel is not registered',
        error,
      );
    }

    _advertising = true;
    coreLog.info('BLE rendezvous advertising as "$rendezvousId" '
        '(${encoded.length} byte payload)');
  }

  @override
  Future<void> stop() async {
    _advertising = false;
    try {
      await channel.invokeMethod<void>('stopAdvertising');
    } on PlatformException catch (error) {
      coreLog.warning('stopAdvertising failed', error);
    } on MissingPluginException {
      // Nothing to stop on a VM or unregistered platform.
    }
  }

  /// Ask the OS whether advertising is possible, and why not if it is not.
  Future<BleCapability> capability() async {
    if (!isSupported) {
      return const BleCapability(
        supported: false,
        reason: 'Not an Android device.',
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

  /// Request the Android 12+ BLE runtime permissions.
  Future<bool> requestPermission() async {
    if (!isSupported) return false;
    try {
      return await channel.invokeMethod<bool>('requestBlePermission') ?? false;
    } on PlatformException catch (error) {
      coreLog.warning('requestBlePermission failed: ${error.message}');
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// Map a native code onto a typed failure, same contract as the hotspot path.
  static BleException _translate(PlatformException error) =>
      BleException(BleFailure.fromName(error.code), error.message ?? '', error);
}
