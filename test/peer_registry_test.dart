import 'dart:async';

import 'package:aero/core/constants.dart';
import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:aero/ui/peer_registry.dart';
import 'package:flutter_test/flutter_test.dart';

/// Discovery stub that emits exactly what a test tells it to.
class _FakeDiscovery implements DiscoveryService {
  _FakeDiscovery();

  final _controller = StreamController<DiscoveredPeer>.broadcast();

  @override
  Stream<DiscoveredPeer> get peers => _controller.stream;

  @override
  String get backendName => 'fake';

  @override
  String? get unavailableReason => null;

  @override
  Future<void> start({required int port, required PeerInfo self}) async {}

  @override
  Future<void> stop() async {}

  @override
  Future<void> dispose() => _controller.close();

  void emit(DiscoveredPeer p) => _controller.add(p);
}

DiscoveredPeer peer(
  String id, {
  String name = 'Peer',
  String host = '192.168.1.5',
  int port = kPreferredPort,
  TrustState trust = TrustState.unknown,
}) =>
    DiscoveredPeer(
      info: PeerInfo(
        deviceId: id,
        deviceName: name,
        os: AeroOs.macos,
        osVersion: '14',
        appVersion: '1.0.0',
        publicKey: 'AAAA',
        protocolVersion: kProtocolVersion,
        capabilities: const {Capability.receive, Capability.send},
        nonce: 'n',
        port: port,
        trustState: trust,
      ),
      address: PeerAddress(host: host, port: port),
      resolvedAt: DateTime(2026, 1, 1),
    );

void main() {
  group('PeerRegistry', () {
    late _FakeDiscovery discovery;

    setUp(() => discovery = _FakeDiscovery());
    tearDown(() => discovery.dispose());

    test('drops our own advertisement', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery.emit(peer('me', name: 'This Mac'));
      await pumpEventQueue();

      expect(registry.count, 0);
    });

    test('keeps peers with an empty device id out', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery.emit(peer(''));
      await pumpEventQueue();

      expect(registry.count, 0);
    });

    test('deduplicates repeated resolves of the same device', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery
        ..emit(peer('a', name: 'First'))
        ..emit(peer('a', name: 'First'))
        ..emit(peer('a', name: 'First'));
      await pumpEventQueue();

      expect(registry.count, 1);
    });

    test('a repeated resolve refreshes last-heard but not first-seen', () async {
      // The TTL measures "last heard from", so a repeating record must extend
      // the lifetime of the entry without rewriting the original timestamp.
      var now = DateTime(2026, 1, 1);
      final registry = PeerRegistry(ttl: const Duration(seconds: 10), clock: () => now)
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery.emit(peer('a'));
      await pumpEventQueue();
      final firstSeen = registry.byId('a')!.resolvedAt;

      now = now.add(const Duration(seconds: 8));
      discovery.emit(peer('a'));
      await pumpEventQueue();

      expect(registry.byId('a')!.resolvedAt, firstSeen,
          reason: 'unchanged address should preserve the original timestamp');
      expect(registry.count, 1);
    });

    test('an address change resets the TTL', () async {
      // A DHCP lease change looks like a new sighting, so it must not be
      // suppressed by an unchanged address.
      var now = DateTime(2026, 1, 1);
      final registry = PeerRegistry(ttl: const Duration(seconds: 10), clock: () => now)
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery.emit(peer('a', host: '192.168.1.5'));
      await pumpEventQueue();
      now = now.add(const Duration(seconds: 8));
      discovery.emit(peer('a', host: '192.168.1.9'));
      await pumpEventQueue();

      expect(registry.byId('a')!.address.host, '192.168.1.9');
      expect(registry.byId('a')!.resolvedAt, now);
    });

    test('notifies listeners on change', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      var notifications = 0;
      registry.addListener(() => notifications++);

      discovery.emit(peer('a'));
      await pumpEventQueue();

      expect(notifications, 1);
    });

    test('enrich replaces the TXT-derived record with the handshake result', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      discovery.emit(peer('a', name: 'Stale Name'));
      await pumpEventQueue();

      registry.enrich('a', peer('a', name: 'Real Name').info);
      expect(registry.byId('a')!.info.deviceName, 'Real Name');
    });

    test('enrich ignores unknown ids', () async {
      final registry = PeerRegistry(clock: () => DateTime(2026, 1, 1))
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      registry.enrich('never-seen', peer('x').info);
      expect(registry.count, 0);
    });

    test('orders peers most-recently-heard first', () async {
      var now = DateTime(2026, 1, 1);
      final registry = PeerRegistry(clock: () => now)
        ..attach(discovery, selfDeviceId: 'me');
      addTearDown(registry.dispose);

      // Emitted one at a time with a flush between: a broadcast stream delivers
      // asynchronously, so batching these would make every record see the same
      // clock reading and the ordering assertion would be meaningless.
      for (final id in ['a', 'b', 'c']) {
        discovery.emit(peer(id));
        await pumpEventQueue();
        now = now.add(const Duration(seconds: 1));
      }

      expect(registry.peers.map((p) => p.deviceId), ['c', 'b', 'a']);
    });
  });

  group('PeerAddress', () {
    test('builds a URI from a plain IPv4 host', () {
      expect(PeerAddress(host: '192.168.1.5', port: 44353).uri.host, '192.168.1.5');
    });

    test('brackets IPv6 literals so the URI parses', () {
      // Without brackets, `aero://fe80::1:44353` is ambiguous and Uri.parse
      // would mis-split host from port.
      final uri = PeerAddress(host: 'fe80::1', port: 44353).uri;
      expect(uri.host, 'fe80::1');
      expect(uri.port, 44353);
    });

    test('does not double-bracket an already bracketed host', () {
      expect(PeerAddress(host: '[::1]', port: 1).uri.host, '::1');
    });

    test('equality is by host and port', () {
      expect(PeerAddress(host: '1.2.3.4', port: 1), PeerAddress(host: '1.2.3.4', port: 1));
      expect(PeerAddress(host: '1.2.3.4', port: 1), isNot(PeerAddress(host: '1.2.3.4', port: 2)));
    });
  });
}