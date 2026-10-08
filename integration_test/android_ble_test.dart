// ignore_for_file: avoid_print
import 'package:aero/core/network/android_ble.dart';
import 'package:aero/core/network/ble_rendezvous.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Real-device probe for the Android BLE advertising path.
///
/// Runs on the device, driving the same [AndroidBleAdvertiser] the app uses over
/// the real `aero/ble` channel. This is the half of Phase 2 that a unit test
/// cannot reach: the channel is mocked in `ble_rendezvous_test.dart`, so only a
/// real radio can prove that `BluetoothLeAdvertiser` + the GATT server actually
/// come up on this ROM.
///
///   flutter test integration_test/android_ble_test.dart -d 192.168.1.8:37195
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Android BLE advertise round-trip on the real device', (tester) async {
    final advertiser = AndroidBleAdvertiser();

    print('SUPPORTED ${advertiser.isSupported} reason="${advertiser.unsupportedReason}"');
    expect(advertiser.isSupported, isTrue,
        reason: 'BLE advertising is Android-only and this is an Android device');

    // Android 12+ splits Bluetooth into ADVERTISE/CONNECT runtime permissions;
    // the native side prompts for them and reports the outcome.
    final granted = await advertiser.requestPermission();
    print('PERMISSION granted=$granted');
    expect(granted, isTrue, reason: 'grant Bluetooth advertise/connect on API 31');

    final payload = BleRendezvous(
      deviceName: 'Integration Phone',
      deviceId: 'ab12cd34ef567890ab12cd34ef567890',
      // A realistic hint set: an endpoint plus hotspot credentials, exactly
      // what a real rendezvous carries when no shared subnet exists.
      host: '192.168.43.1',
      port: 44353,
      nonce: 'integration-nonce',
      hotspotSsid: 'AndroidShare_TEST',
      hotspotPsk: 'testpass123',
      os: 'android',
    );

    // `start` returns normally only once the OS confirms advertising; a radio
    // that refuses (AIRPLANE_MODE, radio off, a vendor switch) throws here.
    await advertiser.start(rendezvousId: 'integration-test', payload: payload);
    print('ADVERTISING ${advertiser.isAdvertising}');
    expect(advertiser.isAdvertising, isTrue);

    // Hold it briefly so the advertisement is genuinely on air, not just
    // registered, then tear it down.
    await Future<void>.delayed(const Duration(seconds: 3));

    await advertiser.stop();
    print('STOPPED advertising=${advertiser.isAdvertising}');
    expect(advertiser.isAdvertising, isFalse);

    // Restart proves the advertiser can be reused after a stop rather than
    // needing a fresh instance on every rendezvous.
    await advertiser.start(rendezvousId: 'integration-test-2', payload: payload);
    expect(advertiser.isAdvertising, isTrue);
    await advertiser.stop();
    print('DONE');
  });
}
