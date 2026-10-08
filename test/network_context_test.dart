import 'dart:io';

import 'package:aero/core/network/network_context.dart';
import 'package:flutter_test/flutter_test.dart';

/// The probe must distinguish "has a dialable address" from "a peer can actually
/// reach us here". A phone on cellular has a real address on `rmnet_data1`, but
/// it sits behind the carrier's NAT and mDNS cannot cross it. Counting that as a
/// shared LAN is the bug this file pins down: the app would report
/// `LAN_AVAILABLE` on a device with no Wi-Fi, and the peer list would stay empty
/// with no explanation.
void main() {
  group('classifyInterface', () {
    test('recognises Wi-Fi names', () {
      expect(classifyInterface('wlan0'), InterfaceKind.wifi);
      expect(classifyInterface('wlan1'), InterfaceKind.wifi);
      expect(classifyInterface('wl0p1'), InterfaceKind.wifi);
      expect(classifyInterface('ap0'), InterfaceKind.wifi);
    });

    test('recognises ethernet names', () {
      expect(classifyInterface('en0'), InterfaceKind.ethernet);
      expect(classifyInterface('eth0'), InterfaceKind.ethernet);
      expect(classifyInterface('enp3s0'), InterfaceKind.ethernet);
      expect(classifyInterface('eno1'), InterfaceKind.ethernet);
      expect(classifyInterface('veth1234'), InterfaceKind.ethernet);
      expect(classifyInterface('Ethernet'), InterfaceKind.ethernet);
    });

    test('recognises cellular names, which are NEVER a peer link', () {
      expect(classifyInterface('rmnet_data0'), InterfaceKind.cellular);
      expect(classifyInterface('rmnet_data1'), InterfaceKind.cellular);
      expect(classifyInterface('rmnet0'), InterfaceKind.cellular);
      expect(classifyInterface('ccmni0'), InterfaceKind.cellular);
      expect(classifyInterface('pdp_ip0'), InterfaceKind.cellular);
      expect(classifyInterface('wwan0'), InterfaceKind.cellular);
    });

    test('recognises tunnels', () {
      expect(classifyInterface('utun0'), InterfaceKind.vpn);
      expect(classifyInterface('utun3'), InterfaceKind.vpn);
      expect(classifyInterface('tun0'), InterfaceKind.vpn);
      expect(classifyInterface('wg0'), InterfaceKind.vpn);
      expect(classifyInterface('ipsec0'), InterfaceKind.vpn);
      expect(classifyInterface('ppp0'), InterfaceKind.vpn);
    });

    test('recognises loopback', () {
      expect(classifyInterface('lo'), InterfaceKind.loopback);
      expect(classifyInterface('lo0'), InterfaceKind.loopback);
    });

    test('an unknown name is a LAN candidate, not silently ignored', () {
      // Bias matters: a false positive costs one doomed dial, a false negative
      // could hide a real network on an OS whose naming we did not anticipate.
      expect(classifyInterface('weird42'), InterfaceKind.other);
      expect(InterfaceKind.other.isSharedLinkCandidate, isTrue);
    });

    test('only wifi, ethernet and other are shared-link candidates', () {
      expect(InterfaceKind.wifi.isSharedLinkCandidate, isTrue);
      expect(InterfaceKind.ethernet.isSharedLinkCandidate, isTrue);
      expect(InterfaceKind.other.isSharedLinkCandidate, isTrue);
      expect(InterfaceKind.cellular.isSharedLinkCandidate, isFalse);
      expect(InterfaceKind.vpn.isSharedLinkCandidate, isFalse);
      expect(InterfaceKind.loopback.isSharedLinkCandidate, isFalse);
    });
  });

  group('NetworkInterfaceSummary.isLanCandidate', () {
    test('a Wi-Fi interface with an address is a candidate', () {
      const i = NetworkInterfaceSummary(
        name: 'wlan0',
        addresses: ['192.168.1.8'],
        isLoopback: false,
        kind: InterfaceKind.wifi,
      );
      expect(i.isLanCandidate, isTrue);
    });

    test('a cellular interface with an address is NOT a candidate', () {
      const i = NetworkInterfaceSummary(
        name: 'rmnet_data1',
        addresses: ['10.20.30.40'],
        isLoopback: false,
        kind: InterfaceKind.cellular,
      );
      expect(i.isUsable, isTrue, reason: 'it does have an address');
      expect(i.isLanCandidate, isFalse, reason: 'but a peer cannot reach it');
    });

    test('a VPN interface is not a candidate', () {
      const i = NetworkInterfaceSummary(
        name: 'utun0',
        addresses: ['10.8.0.2'],
        isLoopback: false,
        kind: InterfaceKind.vpn,
      );
      expect(i.isLanCandidate, isFalse);
    });

    test('a Wi-Fi interface with no address is not a candidate', () {
      const i = NetworkInterfaceSummary(
        name: 'wlan0',
        addresses: [],
        isLoopback: false,
        kind: InterfaceKind.wifi,
      );
      expect(i.isLanCandidate, isFalse);
    });
  });

  group('NetworkContext classification', () {
    NetworkContext ctx(List<NetworkInterfaceSummary> interfaces) =>
        NetworkContext(interfaces: interfaces, reason: NetworkContextReason.lanAvailable);

    test('lanInterfaces excludes cellular even when it has an address', () {
      final c = ctx(const [
        NetworkInterfaceSummary(
          name: 'wlan0',
          addresses: ['192.168.1.8'],
          isLoopback: false,
          kind: InterfaceKind.wifi,
        ),
        NetworkInterfaceSummary(
          name: 'rmnet_data1',
          addresses: ['10.20.30.40'],
          isLoopback: false,
          kind: InterfaceKind.cellular,
        ),
      ]);
      expect(c.lanInterfaces.map((i) => i.name), ['wlan0']);
      expect(c.nonShareableInterfaces.map((i) => i.name), ['rmnet_data1']);
    });

    test('a phone with only cellular has no LAN candidate', () {
      final c = ctx(const [
        NetworkInterfaceSummary(
          name: 'rmnet_data1',
          addresses: ['10.20.30.40'],
          isLoopback: false,
          kind: InterfaceKind.cellular,
        ),
        NetworkInterfaceSummary(
          name: 'lo',
          addresses: ['127.0.0.1'],
          isLoopback: true,
          kind: InterfaceKind.loopback,
        ),
      ]);
      expect(c.lanInterfaces, isEmpty);
      expect(c.hasSharedLanCandidate, isFalse);
    });

    test('the summary names the excluded link types', () {
      const c = NetworkContext(
        interfaces: [
          NetworkInterfaceSummary(
            name: 'rmnet_data1',
            addresses: ['10.20.30.40'],
            isLoopback: false,
            kind: InterfaceKind.cellular,
          ),
        ],
        reason: NetworkContextReason.noSharedSubnet,
      );
      expect(c.summary, contains('rmnet_data1'));
      expect(c.summary, contains('cellular'));
      expect(c.summary, contains('cannot reach'));
    });
  });

  group('probeNetworkContext (real machine)', () {
    test('classifies every interface it reports', () async {
      final c = await probeNetworkContext();
      for (final i in c.interfaces) {
        // Every interface must have a kind; `other` is legal but must be a
        // deliberate fallback, never a misclassification of a known name.
        expect(i.kind, isNotNull);
      }
      // The reason must agree with the candidate list.
      if (c.reason == NetworkContextReason.lanAvailable) {
        expect(c.lanInterfaces, isNotEmpty);
      } else {
        expect(c.lanInterfaces, isEmpty);
      }
    });

    test('a real cellular interface on this machine is not a LAN candidate', () async {
      final c = await probeNetworkContext();
      // If this machine has a cellular interface, it must be excluded. On a Mac
      // there may be none, in which case the assertion is vacuously true.
      final cellular =
          c.interfaces.where((i) => i.kind == InterfaceKind.cellular).toList();
      for (final i in cellular) {
        expect(i.isLanCandidate, isFalse);
        expect(c.lanInterfaces.map((n) => n.name), isNot(contains(i.name)));
      }
      expect(InternetAddress.anyIPv4.isLoopback, isFalse);
    });
  });
}
