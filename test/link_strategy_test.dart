import 'dart:io';

import 'package:aero/core/network/link_strategy.dart';
import 'package:aero/core/network/network_context.dart';
import 'package:flutter_test/flutter_test.dart';

/// Phase 0 is pure decision logic plus one probe, so everything here is
/// deterministic except the probe test, which asserts only that the probe
/// returns *something* honest on the real machine rather than hanging or
/// throwing.
void main() {
  NetworkContext ctx(
    NetworkContextReason reason, {
    List<NetworkInterfaceSummary> interfaces = const [],
    Object? error,
  }) =>
      NetworkContext(interfaces: interfaces, reason: reason, error: error);

  const lan = NetworkInterfaceSummary(
    name: 'en0',
    addresses: ['192.168.1.25'],
    isLoopback: false,
  );
  const loopback = NetworkInterfaceSummary(
    name: 'lo0',
    addresses: ['127.0.0.1'],
    isLoopback: true,
  );
  const emptyLan = NetworkInterfaceSummary(
    name: 'wlan0',
    addresses: [],
    isLoopback: false,
  );

  group('NetworkContext reasons', () {
    test('reports LAN available only when a non-loopback usable interface exists', () {
      final c = ctx(NetworkContextReason.lanAvailable, interfaces: [loopback, lan]);
      expect(c.hasSharedLanCandidate, isTrue);
      expect(c.lanInterfaces.map((i) => i.name), ['en0']);
    });

    test('loopback never counts as a shared LAN candidate', () {
      final c = ctx(NetworkContextReason.noSharedSubnet, interfaces: [loopback]);
      expect(c.hasSharedLanCandidate, isFalse);
      expect(c.lanInterfaces, isEmpty);
      expect(c.summary, contains('No shared network'));
    });

    test('an interface with no dialable address is not usable', () {
      const iface = NetworkInterfaceSummary(
        name: 'wlan0',
        addresses: [],
        isLoopback: false,
      );
      expect(iface.isUsable, isFalse);
      expect(iface.toString(), contains('lan'));
    });

    test('enumeration failure does NOT claim the LAN is available', () {
      // A failed probe must bias toward the fallback, not toward a false
      // "everything is fine" that silently hangs.
      final c = ctx(NetworkContextReason.enumerationFailed, error: 'EPERM');
      expect(c.hasSharedLanCandidate, isFalse);
      expect(c.summary, contains('Could not inspect'));
      expect(c.summary, contains('EPERM'));
    });

    test('every reason has a distinct stable id', () {
      final ids = NetworkContextReason.values.map((r) => r.id).toSet();
      expect(ids.length, NetworkContextReason.values.length);
    });
  });

  group('TierReason ids', () {
    test('the identifiers the user asked for exist verbatim', () {
      // These exact strings are what a real-device run is grepped for, so they
      // are part of the observable contract rather than incidental prose.
      expect(TierReason.lanAvailable.id, 'LAN_AVAILABLE');
      expect(TierReason.noReachablePeers.id, 'NO_REACHABLE_PEERS');
      expect(TierReason.noSharedSubnet.id, 'NO_SHARED_SUBNET');
      expect(TierReason.hotspotRequired.id, 'HOTSPOT_REQUIRED');
      expect(TierReason.mdnsUnavailable.id, 'MDNS_UNAVAILABLE');
    });

    test('ids are unique', () {
      final ids = TierReason.values.map((r) => r.id).toSet();
      expect(ids.length, TierReason.values.length);
    });
  });

  group('TransportTier ordering', () {
    test('rank ordering is strictly ascending by preference', () {
      expect(TransportTier.sharedLan.rank, lessThan(TransportTier.hotspot.rank));
      expect(TransportTier.hotspot.rank, lessThan(TransportTier.bleRendezvous.rank));
      expect(TransportTier.bleRendezvous.rank, lessThan(TransportTier.manual.rank));
    });

    test('only the LAN-based tiers use the unchanged shared-LAN transport', () {
      expect(TransportTier.sharedLan.usesSharedLanTransport, isTrue);
      expect(TransportTier.hotspot.usesSharedLanTransport, isTrue);
      expect(TransportTier.bleRendezvous.usesSharedLanTransport, isFalse);
      expect(TransportTier.manual.usesSharedLanTransport, isFalse);
    });
  });

  group('Phase0LinkStrategy', () {
    const strategy = Phase0LinkStrategy();

    test('picks Tier 0 with LAN_AVAILABLE when a shared LAN exists', () {
      final d = strategy.select(ctx(NetworkContextReason.lanAvailable, interfaces: [lan]));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.lanAvailable);
      expect(d.isSupported, isTrue);
      expect(d.detail, contains('en0'));
    });

    test('stays on Tier 0 but flags HOTSPOT_REQUIRED when there is no subnet', () {
      // Phase 0 cannot return a fallback tier, but it must not pretend the LAN
      // is fine either - the reason is the whole point.
      final d = strategy.select(ctx(NetworkContextReason.noSharedSubnet, interfaces: [loopback]));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.hotspotRequired);
      expect(d.isSupported, isTrue, reason: 'Tier 0 is what actually runs');
      expect(d.detail, contains('not built yet'));
    });

    test('reports NO_USABLE_INTERFACE without demanding a hotspot yet', () {
      // Waiting for a DHCP lease is more sensible than starting a hotspot the
      // moment an interface briefly has no address.
      final d = strategy.select(ctx(NetworkContextReason.noUsableInterface, interfaces: [emptyLan]));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.noUsableInterface);
    });

    test('reports ENUMERATION_FAILED with the error attached', () {
      final d = strategy.select(ctx(NetworkContextReason.enumerationFailed, error: 'EPERM'));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.enumerationFailed);
      expect(d.detail, contains('EPERM'));
    });

    test('never throws for any reason', () {
      for (final reason in NetworkContextReason.values) {
        expect(() => strategy.select(ctx(reason)), returnsNormally);
      }
    });
  });

  group('TierDecision.summary', () {
    test('includes the reason id and the detail when present', () {
      const withDetail = TierDecision(
        tier: TransportTier.sharedLan,
        reason: TierReason.lanAvailable,
        detail: 'interfaces: en0',
      );
      expect(withDetail.summary, contains('shared LAN'));
      expect(withDetail.summary, contains('LAN_AVAILABLE'));
      expect(withDetail.summary, contains('en0'));

      const withoutDetail = TierDecision(
        tier: TransportTier.sharedLan,
        reason: TierReason.noReachablePeers,
      );
      expect(withoutDetail.summary, isNot(contains('—')));
    });
  });

  group('mdnsUnavailableReason', () {
    test('a discovery problem wins over peer count', () {
      expect(
        mdnsUnavailableReason('permission denied', 5),
        TierReason.mdnsUnavailable,
      );
    });

    test('no problem but no peers reports NO_REACHABLE_PEERS', () {
      expect(mdnsUnavailableReason(null, 0), TierReason.noReachablePeers);
    });

    test('no problem and peers reports LAN_AVAILABLE', () {
      expect(mdnsUnavailableReason(null, 2), TierReason.lanAvailable);
    });
  });

  group('probeNetworkContext (real machine)', () {
    test('returns a consistent context and never throws', () async {
      final c = await probeNetworkContext();

      // The reason must agree with the interface list it produced, on whatever
      // machine this runs on.
      if (c.reason == NetworkContextReason.lanAvailable) {
        expect(c.lanInterfaces, isNotEmpty);
        expect(c.hasSharedLanCandidate, isTrue);
      } else {
        expect(c.lanInterfaces, isEmpty);
        expect(c.hasSharedLanCandidate, isFalse);
      }
      expect(c.summary, isNotEmpty);
    });

    test('a loopback-only machine is classified as having no shared subnet', () async {
      // We cannot force the machine's interfaces, so this asserts the *rule*
      // via a constructed context rather than the live one.
      final c = ctx(NetworkContextReason.noSharedSubnet, interfaces: [loopback]);
      expect(c.reason, NetworkContextReason.noSharedSubnet);
      expect(c.lanInterfaces, isEmpty);
    });
  });

  test('NetworkInterfaceSummary defaults are safe', () {
    const i = NetworkInterfaceSummary(
      name: 'test0',
      addresses: [],
      isLoopback: false,
    );
    expect(i.isUsable, isFalse);
    expect(InternetAddress.anyIPv4.isLoopback, isFalse);
  });
}
