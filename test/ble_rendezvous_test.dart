import 'package:aero/core/network/android_ble.dart';
import 'package:aero/core/network/ble_rendezvous.dart';
import 'package:aero/core/network/link_strategy.dart';
import 'package:aero/core/network/macos_ble.dart';
import 'package:aero/core/network/network_context.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Phase 2 tests. The BLE layer is exercised through fake platform channels, so
/// every branch - including the failure callbacks a real radio produces rarely -
/// is reachable without hardware.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // ---------------------------------------------------------------------------
  // The untrusted rendezvous payload
  // ---------------------------------------------------------------------------

  group('BleRendezvous parsing', () {
    test('parses a full, well-formed payload', () {
      final r = BleRendezvous.tryFromJson({
        'deviceName': "Alex's phone",
        'deviceId': 'abc123',
        'host': '192.168.43.1',
        'port': 44353,
        'nonce': 'n0nce',
        'os': 'android',
        'rssi': -42,
      });
      expect(r, isNotNull);
      expect(r!.deviceName, "Alex's phone");
      expect(r.deviceId, 'abc123');
      expect(r.host, '192.168.43.1');
      expect(r.port, 44353);
      expect(r.hasEndpoint, isTrue);
      expect(r.isActionable, isTrue);
      expect(r.rssi, -42);
    });

    test('accepts a hotspot-only rendezvous with no endpoint', () {
      final r = BleRendezvous.tryFromJson({
        'deviceName': 'phone',
        'deviceId': 'abc123',
        'hotspotSsid': 'AndroidShare_1234',
        'hotspotPsk': 'pass',
      });
      expect(r, isNotNull);
      expect(r!.hasEndpoint, isFalse);
      expect(r.hasHotspot, isTrue);
      expect(r.isActionable, isTrue);
    });

    test('drops a payload with no device id', () {
      expect(BleRendezvous.tryFromJson({'deviceName': 'x'}), isNull);
      expect(BleRendezvous.tryFromJson({'deviceId': '  '}), isNull);
    });

    test('drops a payload with nothing actionable', () {
      // A rendezvous that is neither an endpoint nor hotspot credentials is
      // noise; showing it would send the user chasing a phantom.
      expect(
        BleRendezvous.tryFromJson({'deviceId': 'abc', 'deviceName': 'x'}),
        isNull,
      );
    });

    test('rejects a non-dialable host but keeps the rendezvous if a hotspot exists', () {
      final r = BleRendezvous.tryFromJson({
        'deviceId': 'abc',
        'host': 'evil.com/path',
        'hotspotSsid': 'Something',
      });
      expect(r, isNotNull);
      expect(r!.host, isNull, reason: 'a hostname/path must not survive');
      expect(r.hasHotspot, isTrue);
    });

    test('rejects an out-of-range port', () {
      final r = BleRendezvous.tryFromJson({
        'deviceId': 'abc',
        'host': '192.168.1.5',
        'port': 99999,
      });
      expect(r, isNull, reason: 'no endpoint and no hotspot means unusable');
    });

    test('clips and strips control characters from untrusted text', () {
      final r = BleRendezvous.tryFromJson({
        'deviceId': 'abc',
        'deviceName': 'bad\u202Ename\x07here',
        'hotspotSsid': 's',
      });
      expect(r, isNotNull);
      expect(r!.deviceName, isNot(contains('\u202E')));
      expect(r.deviceName, isNot(contains('\x07')));
    });

    test('round-trips through JSON', () {
      const original = BleRendezvous(
        deviceName: 'phone',
        deviceId: 'abc',
        host: '192.168.1.5',
        port: 44353,
        nonce: 'n',
        os: 'android',
      );
      final back = BleRendezvous.tryFromJson(original.toJson());
      expect(back, isNotNull);
      expect(back!.deviceId, original.deviceId);
      expect(back.host, original.host);
      expect(back.port, original.port);
    });
  });

  group('isValidDialableHost', () {
    test('accepts private IPv4 ranges', () {
      expect(isValidDialableHost('192.168.1.5'), isTrue);
      expect(isValidDialableHost('10.0.0.4'), isTrue);
      expect(isValidDialableHost('172.16.5.9'), isTrue);
    });

    test('rejects loopback, wildcard, and multicast', () {
      // A peer advertising loopback would make this device dial itself.
      expect(isValidDialableHost('127.0.0.1'), isFalse);
      expect(isValidDialableHost('0.0.0.0'), isFalse);
      expect(isValidDialableHost('224.0.0.251'), isFalse);
    });

    test('rejects link-local', () {
      expect(isValidDialableHost('169.254.1.1'), isFalse);
      expect(isValidDialableHost('fe80::1'), isFalse);
    });

    test('rejects a hostname, since DNS may be the broken thing', () {
      expect(isValidDialableHost('example.local'), isFalse);
      expect(isValidDialableHost('evil.com/x'), isFalse);
      expect(isValidDialableHost('host with spaces'), isFalse);
    });

    test('accepts a global IPv6 address', () {
      expect(isValidDialableHost('2001:db8::1'), isTrue);
    });
  });

  group('BleFailure', () {
    test('round-trips every id', () {
      for (final f in BleFailure.values) {
        expect(BleFailure.fromName(f.id), f);
      }
    });

    test('an unknown id degrades to generic', () {
      expect(BleFailure.fromName('nonsense'), BleFailure.generic);
      expect(BleFailure.fromName(null), BleFailure.generic);
    });
  });

  // ---------------------------------------------------------------------------
  // Platform implementations
  // ---------------------------------------------------------------------------

  group('Unsupported BLE implementations', () {
    test('advertiser reports unsupported and throws a typed failure', () async {
      const a = UnsupportedBleAdvertiser('nope');
      expect(a.isSupported, isFalse);
      expect(a.isAdvertising, isFalse);
      await expectLater(
        a.start(
          rendezvousId: 'x',
          payload: const BleRendezvous(deviceName: 'x', deviceId: 'y', host: '1.2.3.4', port: 1),
        ),
        throwsA(isA<BleException>()
            .having((e) => e.failure, 'failure', BleFailure.unsupported)),
      );
      await a.stop();
    });

    test('scanner reports unsupported and throws a typed failure', () async {
      const s = UnsupportedBleScanner('nope');
      expect(s.isSupported, isFalse);
      await expectLater(
        s.scanOnce(),
        throwsA(isA<BleException>()
            .having((e) => e.failure, 'failure', BleFailure.unsupported)),
      );
      await s.stop();
    });
  });

  group('AndroidBleAdvertiser', () {
    const channel = MethodChannel('aero/ble');
    late List<MethodCall> calls;

    setUp(() {
      calls = [];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        switch (call.method) {
          case 'startAdvertising':
            return null;
          case 'stopAdvertising':
            return null;
          case 'requestBlePermission':
            return true;
          case 'bleCapability':
            return <Object?, Object?>{
              'supported': true,
              'reason': '',
              'permission': 'android.permission.BLUETOOTH_ADVERTISE',
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

    test('start sends the encoded payload and marks advertising', () async {
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      await a.start(
        rendezvousId: 'abc123',
        payload: const BleRendezvous(
          deviceName: 'phone',
          deviceId: 'abc123',
          host: '192.168.43.1',
          port: 44353,
        ),
      );
      expect(a.isAdvertising, isTrue);
      final call = calls.firstWhere((c) => c.method == 'startAdvertising');
      final args = call.arguments as Map<Object?, Object?>;
      expect(args['rendezvousId'], 'abc123');
      expect(args['payload'], contains('192.168.43.1'));
    });

    test('stop clears the advertising flag and invokes the channel', () async {
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      await a.start(
        rendezvousId: 'x',
        payload: const BleRendezvous(deviceName: 'p', deviceId: 'abc', host: '10.0.0.1', port: 1),
      );
      await a.stop();
      expect(a.isAdvertising, isFalse);
      expect(calls.any((c) => c.method == 'stopAdvertising'), isTrue);
      // Stop again is safe.
      await a.stop();
    });

    test('a PlatformException maps to a typed failure', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'startAdvertising') {
          throw PlatformException(code: BleFailure.bluetoothOff.id, message: 'off');
        }
        return null;
      });
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      await expectLater(
        a.start(
          rendezvousId: 'x',
          payload: const BleRendezvous(deviceName: 'p', deviceId: 'abc', host: '10.0.0.1', port: 1),
        ),
        throwsA(isA<BleException>()
            .having((e) => e.failure, 'failure', BleFailure.bluetoothOff)),
      );
      expect(a.isAdvertising, isFalse,
          reason: 'a failed start must not leave the advertising flag set');
    });

    test('every native error code maps to its typed failure', () async {
      for (final f in BleFailure.values) {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'startAdvertising') {
            throw PlatformException(code: f.id);
          }
          return null;
        });
        final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
        await expectLater(
          a.start(
            rendezvousId: 'x',
            payload: const BleRendezvous(deviceName: 'p', deviceId: 'abc', host: '10.0.0.1', port: 1),
          ),
          throwsA(isA<BleException>().having((e) => e.failure, 'failure', f)),
          reason: 'code ${f.id}',
        );
      }
    });

    test('an oversized payload is refused before it reaches the radio', () async {
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      await expectLater(
        a.start(
          rendezvousId: 'x',
          payload: BleRendezvous(
            deviceName: 'x' * 900,
            deviceId: 'abc',
            host: '10.0.0.1',
            port: 1,
          ),
        ),
        throwsA(isA<BleException>()),
      );
      expect(calls.any((c) => c.method == 'startAdvertising'), isFalse);
    });

    test('capability reports support and the required permission', () async {
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      final cap = await a.capability();
      expect(cap.supported, isTrue);
      expect(cap.permission, contains('BLUETOOTH_ADVERTISE'));
    });

    test('requestPermission returns the channel answer', () async {
      final a = AndroidBleAdvertiser(channel: channel, isSupportedOverride: true);
      expect(await a.requestPermission(), isTrue);
    });
  });

  group('MacBleScanner', () {
    const channel = MethodChannel('aero/ble');

    setUp(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        switch (call.method) {
          case 'scanForRendezvous':
            return <Object?, Object?>{
              'deviceName': 'phone',
              'deviceId': 'abc123',
              'host': '192.168.43.1',
              'port': 44353,
            };
          case 'stopScan':
            return null;
          case 'bleCapability':
            return <Object?, Object?>{'supported': true, 'reason': ''};
          default:
            return null;
        }
      });
    });

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    test('a scan returns a sanitised rendezvous', () async {
      final s = MacBleScanner(channel: channel, isSupportedOverride: true);
      final found = await s.scanOnce();
      expect(found, isNotNull);
      expect(found!.deviceId, 'abc123');
      expect(found.host, '192.168.43.1');
    });

    test('a null result means nothing found, not an error', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'scanForRendezvous') return null;
        return null;
      });
      final s = MacBleScanner(channel: channel, isSupportedOverride: true);
      expect(await s.scanOnce(), isNull);
    });

    test('an unusable payload is dropped rather than returned', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'scanForRendezvous') {
          return <Object?, Object?>{'deviceId': 'abc'}; // nothing actionable
        }
        return null;
      });
      final s = MacBleScanner(channel: channel, isSupportedOverride: true);
      expect(await s.scanOnce(), isNull);
    });

    test('a PlatformException maps to a typed failure', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'scanForRendezvous') {
          throw PlatformException(code: BleFailure.permissionDenied.id);
        }
        return null;
      });
      final s = MacBleScanner(channel: channel, isSupportedOverride: true);
      await expectLater(
        s.scanOnce(),
        throwsA(isA<BleException>()
            .having((e) => e.failure, 'failure', BleFailure.permissionDenied)),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Tier transition
  // ---------------------------------------------------------------------------

  group('Phase2LinkStrategy', () {
    NetworkContext ctx(NetworkContextReason reason) =>
        NetworkContext(interfaces: const [], reason: reason);

    test('a usable LAN wins over every fallback', () {
      const s = Phase2LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
      final d = s.select(ctx(NetworkContextReason.lanAvailable));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.lanAvailable);
    });

    test('no subnet + can host selects the hotspot, not BLE', () {
      const s = Phase2LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.hotspot);
      expect(d.reason, TierReason.hotspotRequired);
    });

    test('no subnet + cannot host + BLE selects the BLE tier', () {
      const s = Phase2LinkStrategy(canHostHotspot: false, canBleRendezvous: true);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.bleRendezvous);
      expect(d.reason, TierReason.bleRendezvous);
    });

    test('no subnet + cannot host + no BLE reports the honest gap', () {
      const s = Phase2LinkStrategy(canHostHotspot: false, canBleRendezvous: false);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.hotspotRequired);
      expect(d.detail, contains('neither host a hotspot nor use BLE'));
    });

    test('an unusable interface still waits rather than starting BLE', () {
      const s = Phase2LinkStrategy(canHostHotspot: false, canBleRendezvous: true);
      final d = s.select(ctx(NetworkContextReason.noUsableInterface));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.noUsableInterface);
    });

    test('never throws for any reason and any capability combination', () {
      for (final host in [true, false]) {
        for (final ble in [true, false]) {
          final s = Phase2LinkStrategy(canHostHotspot: host, canBleRendezvous: ble);
          for (final reason in NetworkContextReason.values) {
            expect(() => s.select(ctx(reason)), returnsNormally);
          }
        }
      }
    });

    test('NO_REACHABLE_PEERS still never selects a fallback', () {
      // The rule that spans every phase: an empty peer list must not turn on a
      // radio. Verified by the fact that the network reason is what drives the
      // tier, and noReachablePeers is not a NetworkContextReason at all.
      expect(mdnsUnavailableReason(null, 0), TierReason.noReachablePeers);
      const s = Phase2LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
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

    test('BLE is discovery-only, so it does not use the shared-LAN transport', () {
      expect(TransportTier.bleRendezvous.usesSharedLanTransport, isFalse);
    });
  });

  group('full tier ladder (Phase 0 -> 1 -> 2)', () {
    final context = NetworkContext(
      interfaces: const [],
      reason: NetworkContextReason.noSharedSubnet,
    );

    test('each phase escalates one step where it can', () {
      expect(const Phase0LinkStrategy().select(context).tier, TransportTier.sharedLan);
      expect(
        const Phase1LinkStrategy(canHostHotspot: true).select(context).tier,
        TransportTier.hotspot,
      );
      expect(
        const Phase2LinkStrategy(canHostHotspot: false, canBleRendezvous: true)
            .select(context)
            .tier,
        TransportTier.bleRendezvous,
      );
    });

    test('all three agree the LAN wins when it is usable', () {
      final lan = NetworkContext(
        interfaces: const [
          NetworkInterfaceSummary(
            name: 'en0',
            addresses: ['192.168.1.5'],
            isLoopback: false,
          ),
        ],
        reason: NetworkContextReason.lanAvailable,
      );
      expect(const Phase0LinkStrategy().select(lan).tier, TransportTier.sharedLan);
      expect(
        const Phase1LinkStrategy(canHostHotspot: true).select(lan).tier,
        TransportTier.sharedLan,
      );
      expect(
        const Phase2LinkStrategy(canHostHotspot: true, canBleRendezvous: true)
            .select(lan)
            .tier,
        TransportTier.sharedLan,
      );
    });
  });
}
