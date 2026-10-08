// ignore_for_file: avoid_print
import 'package:aero/core/network/android_ble.dart';
import 'package:aero/core/network/ble_rendezvous.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Holds a real Android BLE advertisement on air long enough for the Mac's
/// CoreBluetooth central to discover it. This is the cross-platform half of
/// Phase 2 that neither device can prove alone:
///
///   * `android_ble_test.dart` proves the radio advertises;
///   * `macos_ble_scan_test.dart` proves the Mac can scan;
///   * this run overlaps the two so the rendezvous actually crosses the air.
///
/// Run on the phone, then scan from the Mac inside the hold window:
///   flutter test integration_test/android_ble_rendezvous_test.dart -d 192.168.1.8:37195
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Android advertises a rendezvous long enough for a central',
      (tester) async {
    final advertiser = AndroidBleAdvertiser();
    expect(advertiser.isSupported, isTrue);

    final granted = await advertiser.requestPermission();
    expect(granted, isTrue, reason: 'grant Bluetooth advertise/connect');
    print('PERMISSION granted=$granted');

    final payload = BleRendezvous(
      deviceName: 'Rendezvous Phone',
      deviceId: 'rdv0123456789abcdef0123456789abcd',
      host: '192.168.1.8',
      port: 44353,
      nonce: 'rendezvous-nonce',
      os: 'android',
    );

    await advertiser.start(rendezvousId: 'aero-rendezvous', payload: payload);
    print('ADVERTISING=true');
    expect(advertiser.isAdvertising, isTrue);

    // Hold well past a typical central scan window so an overlapping Mac scan
    // has a real chance to land, rather than racing the teardown.
    for (var i = 0; i < 20; i++) {
      await Future<void>.delayed(const Duration(seconds: 2));
      print('HOLD ${(i + 1) * 2}s');
    }

    await advertiser.stop();
    print('STOPPED');
    expect(advertiser.isAdvertising, isFalse);
  }, timeout: const Timeout(Duration(minutes: 2)));
}
