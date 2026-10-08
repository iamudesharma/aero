import 'package:aero/core/network/android_hotspot.dart';
import 'package:aero/core/network/hotspot.dart';
import 'package:aero/core/network/link_strategy.dart';
import 'package:aero/core/network/network_context.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Phase 1 tests. The hotspot layer is exercised through a fake platform
/// channel rather than a real radio, so every branch - including the failure
/// callbacks that a real device produces only occasionally - is reachable.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('HotspotSession', () {
    test('redacted masks the passphrase but not the ssid', () {
      const s = HotspotSession(ssid: 'AndroidShare_1234', psk: 'supersecret', gatewayIp: '192.168.43.1');
      expect(s.redacted, contains('AndroidShare_1234'));
      expect(s.redacted, isNot(contains('supersecret')));
      expect(s.redacted, contains('***'));
      expect(s.redacted, contains('192.168.43.1'));
    });

    test('an open network is marked as such and not masked', () {
      const s = HotspotSession(ssid: 'Open', psk: '', gatewayIp: '');
      expect(s.isOpen, isTrue);
      expect(s.redacted, contains('<open>'));
      expect(s.redacted, contains('gw=unknown'));
    });

    test('round-trips through JSON', () {
      const s = HotspotSession(
        ssid: 'Aero_5G',
        psk: 'pw',
        gatewayIp: '192.168.43.1',
        security: HotspotSecurity.wpa2,
      );
      final back = HotspotSession.tryFromJson(s.toJson());
      expect(back, isNotNull);
      expect(back!.ssid, s.ssid);
      expect(back.psk, s.psk);
      expect(back.gatewayIp, s.gatewayIp);
      expect(back.security, s.security);
    });

    test('rejects a payload with no ssid', () {
      expect(HotspotSession.tryFromJson({'psk': 'x'}), isNull);
      expect(HotspotSession.tryFromJson({'ssid': '  '}), isNull);
      expect(HotspotSession.tryFromJson(null), isNull);
      expect(HotspotSession.tryFromJson('not a map'), isNull);
    });

    test('defaults an unknown security mode to wpa2 rather than open', () {
      final s = HotspotSession.tryFromJson({'ssid': 'x', 'security': 'weird'});
      expect(s!.security, HotspotSecurity.wpa2);
    });
  });

  group('HotspotFailure', () {
    test('round-trips every id', () {
      for (final f in HotspotFailure.values) {
        expect(HotspotFailure.fromName(f.id), f);
      }
    });

    test('an unknown id degrades to generic rather than throwing', () {
      expect(HotspotFailure.fromName('nonsense'), HotspotFailure.generic);
      expect(HotspotFailure.fromName(null), HotspotFailure.generic);
    });
  });

  group('UnsupportedHotspotProvisioner', () {
    test('reports unsupported and carries the reason', () async {
      const p = UnsupportedHotspotProvisioner('No hotspot on this platform.');
      expect(p.isSupported, isFalse);
      expect(p.session, isNull);
      expect(p.unsupportedReason, 'No hotspot on this platform.');

      await expectLater(
        p.start(),
        throwsA(isA<HotspotProvisionException>()
            .having((e) => e.failure, 'failure', HotspotFailure.unsupported)),
      );
      // stop() must be a safe no-op so dispose never throws.
      await p.stop();
    });
  });

  group('AndroidHotspotProvisioner', () {
    const channel = MethodChannel('aero/direct');

    late List<MethodCall> calls;

    setUp(() {
      calls = [];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        switch (call.method) {
          case 'startHotspot':
            return <Object?, Object?>{
              'ssid': 'AndroidShare_4321',
              'psk': 'pass1234',
              'gatewayIp': '192.168.43.1',
              'security': 'wpa2',
            };
          case 'stopHotspot':
            return null;
          case 'requestPermission':
            return true;
          case 'capability':
            return <Object?, Object?>{
              'supported': true,
              'reason': '',
              'permission': 'android.permission.NEARBY_WIFI_DEVICES',
            };
          default:
            return null;
        }
      });
    });

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    test('start returns a normalized session', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      final s = await p.start();
      expect(s.ssid, 'AndroidShare_4321');
      expect(s.psk, 'pass1234');
      expect(s.gatewayIp, '192.168.43.1');
      expect(s.security, HotspotSecurity.wpa2);
      expect(p.session, same(s));
    });

    test('start is idempotent - a second call does not re-invoke the channel', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      final a = await p.start();
      final b = await p.start();
      expect(b.ssid, a.ssid);
      expect(calls.where((c) => c.method == 'startHotspot').length, 1);
    });

    test('concurrent starts coalesce into one channel call', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      final results = await Future.wait([p.start(), p.start(), p.start()]);
      expect(results.map((s) => s.ssid).toSet(), {'AndroidShare_4321'});
      expect(calls.where((c) => c.method == 'startHotspot').length, 1);
    });

    test('stop clears the session and invokes the channel', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      await p.start();
      await p.stop();
      expect(p.session, isNull);
      expect(calls.any((c) => c.method == 'stopHotspot'), isTrue);

      // Stop when already stopped is safe.
      await p.stop();
    });

    test('a PlatformException maps to a typed failure', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'startHotspot') {
          throw PlatformException(
            code: HotspotFailure.permissionDenied.id,
            message: 'nope',
          );
        }
        return null;
      });

      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      await expectLater(
        p.start(),
        throwsA(isA<HotspotProvisionException>()
            .having((e) => e.failure, 'failure', HotspotFailure.permissionDenied)),
      );
      expect(p.session, isNull, reason: 'a failed start must not leave a session');
    });

    test('every native error code maps to its typed failure', () async {
      for (final f in HotspotFailure.values) {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'startHotspot') {
            throw PlatformException(code: f.id);
          }
          return null;
        });
        final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
        await expectLater(
          p.start(),
          throwsA(isA<HotspotProvisionException>()
              .having((e) => e.failure, 'failure', f)),
          reason: 'code ${f.id}',
        );
      }
    });

    test('a malformed payload fails rather than reporting a phantom network', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'startHotspot') return <Object?, Object?>{'psk': 'x'};
        return null;
      });
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      await expectLater(
        p.start(),
        throwsA(isA<HotspotProvisionException>()
            .having((e) => e.failure, 'failure', HotspotFailure.malformed)),
      );
    });

    test('capability reports permission and support', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      final cap = await p.capability();
      expect(cap.supported, isTrue);
      expect(cap.permission, contains('NEARBY'));
    });

    test('requestPermission returns the channel answer', () async {
      final p = AndroidHotspotProvisioner(channel: channel, isSupportedOverride: true);
      expect(await p.requestPermission(), isTrue);
    });
  });

  group('Phase1LinkStrategy', () {
    NetworkContext ctx(NetworkContextReason reason) =>
        NetworkContext(interfaces: const [], reason: reason);

    test('a usable LAN still selects Tier 0 even when hosting is possible', () {
      const s = Phase1LinkStrategy(canHostHotspot: true);
      final d = s.select(ctx(NetworkContextReason.lanAvailable));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.lanAvailable);
    });

    test('no shared subnet selects the hotspot tier when hosting is possible', () {
      const s = Phase1LinkStrategy(canHostHotspot: true);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.hotspot);
      expect(d.reason, TierReason.hotspotRequired);
      expect(d.isSupported, isFalse, reason: 'the hotspot tier is the fallback');
    });

    test('no shared subnet without hosting stays on Tier 0 and says so', () {
      const s = Phase1LinkStrategy(canHostHotspot: false);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.hotspotRequired);
      expect(d.detail, contains('other device must start one'));
    });

    test('an unusable interface waits for a lease rather than starting a hotspot', () {
      const s = Phase1LinkStrategy(canHostHotspot: true);
      final d = s.select(ctx(NetworkContextReason.noUsableInterface));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.noUsableInterface);
    });

    test('never throws for any reason, either capability', () {
      for (final host in [true, false]) {
        final s = Phase1LinkStrategy(canHostHotspot: host);
        for (final reason in NetworkContextReason.values) {
          expect(() => s.select(ctx(reason)), returnsNormally);
        }
      }
    });

    test('NO_REACHABLE_PEERS never selects a fallback tier', () {
      // The rule that matters: an empty peer list on a good network must not
      // silently stand up a hotspot.
      expect(
        mdnsUnavailableReason(null, 0),
        TierReason.noReachablePeers,
      );
      const s = Phase1LinkStrategy(canHostHotspot: true);
      final d = s.select(
        NetworkContext(
          interfaces: const [
            NetworkInterfaceSummary(
              name: 'en0',
              addresses: ['192.168.1.5'],
              isLoopback: false,
            ),
          ],
          reason: NetworkContextReason.lanAvailable,
        ),
      );
      expect(d.tier, TransportTier.sharedLan);
    });

    test('hotspot uses the unchanged shared-LAN transport', () {
      expect(TransportTier.hotspot.usesSharedLanTransport, isTrue);
    });
  });

  group('tier transition (LAN -> hotspot)', () {
    test('Phase 0 stays on Tier 0 where Phase 1 escalates', () {
      final context = NetworkContext(
        interfaces: const [],
        reason: NetworkContextReason.noSharedSubnet,
      );
      expect(const Phase0LinkStrategy().select(context).tier, TransportTier.sharedLan);
      expect(
        const Phase1LinkStrategy(canHostHotspot: true).select(context).tier,
        TransportTier.hotspot,
      );
      // The reason is stable across the two, which is what the log relies on.
      expect(const Phase0LinkStrategy().select(context).reason, TierReason.hotspotRequired);
      expect(
        const Phase1LinkStrategy(canHostHotspot: true).select(context).reason,
        TierReason.hotspotRequired,
      );
    });
  });
}
