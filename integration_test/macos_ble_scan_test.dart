// ignore_for_file: avoid_print
import 'package:aero/core/network/macos_ble.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Real-engine macOS BLE capability probe. Runs on the Mac itself, where
/// CoreBluetooth is real and the TCC prompt can appear.
///
///   flutter test integration_test/macos_ble_scan_test.dart -d macos
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('macOS BLE capability and a real scan', (tester) async {
    final scanner = MacBleScanner();
    print('BLE-SUPPORTED=${scanner.isSupported}');

    final cap = await scanner.capability();
    print('BLE-CAP supported=${cap.supported} reason="${cap.reason}"');
    expect(cap.supported, isTrue,
        reason: 'grant Bluetooth permission to Aero in System Settings');

    // A real scan with nothing advertising should return null, not throw.
    final found = await scanner.scanOnce(timeout: const Duration(seconds: 6));
    print('BLE-FOUND=$found'); //; expected null with no advertiser
    await scanner.stop();
    print('BLE-DONE');
  });
}
