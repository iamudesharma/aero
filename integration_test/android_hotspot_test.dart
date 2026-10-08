// ignore_for_file: avoid_print
import 'package:aero/core/network/android_hotspot.dart';
import 'package:aero/core/network/link_strategy.dart';
import 'package:aero/core/network/network_context.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Real-device probe for the Android hotspot path.
///
/// Runs on the device (integration tests execute on the target), driving the
/// same `AndroidHotspotProvisioner` the app uses over the real `aero/direct`
/// channel. This exercises the native `startLocalOnlyHotspot` path without the
/// UI, which the notification-shade state of a headless test device otherwise
/// gets in the way of.
///
///   flutter test integration_test/android_hotspot_test.dart -d 192.168.1.8:37195
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Android hotspot round-trip on the real device', (tester) async {
    final provisioner = AndroidHotspotProvisioner();

    final cap = await provisioner.capability();
    print('CAPABILITY supported=${cap.supported} reason="${cap.reason}" perm="${cap.permission}"');

    final granted = await provisioner.requestPermission();
    print('PERMISSION granted=$granted');
    expect(granted, isTrue, reason: 'grant ACCESS_FINE_LOCATION on API 31');

    final session = await provisioner.start();
    print('STARTED ssid="${session.ssid}" psk="${session.psk}" gw="${session.gatewayIp}" '
        'security=${session.security}');
    expect(session.ssid, isNotEmpty);

    // The selector must now treat the hotspot as the fallback when no subnet
    // exists. This is the tier transition the app relies on.
    const strategy = Phase1LinkStrategy(canHostHotspot: true);
    final decision = strategy.select(
      const NetworkContext(
        interfaces: [],
        reason: NetworkContextReason.noSharedSubnet,
      ),
    );
    print('TIER ${decision.tier.name} reason=${decision.reason.id}');
    expect(decision.tier, TransportTier.hotspot);

    await provisioner.stop();
    print('STOPPED session=${provisioner.session}');
    expect(provisioner.session, isNull);

    // Restart proves the reservation was released cleanly and not leaked.
    final second = await provisioner.start();
    print('RESTARTED ssid="${second.ssid}"');
    expect(second.ssid, isNotEmpty);
    await provisioner.stop();
    print('DONE');
  });
}
