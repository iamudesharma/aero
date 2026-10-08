import 'dart:convert';

import 'package:aero/core/network/link_strategy.dart';
import 'package:aero/core/network/manual_pairing.dart';
import 'package:aero/core/network/network_context.dart';
import 'package:flutter_test/flutter_test.dart';

/// Phase 3 tests. Manual pairing is pure string handling, so this is exhaustive
/// without any hardware: every accept and reject path, and the full tier ladder
/// ending in `manual`.
void main() {
  group('ManualConnection', () {
    test('builds a URI that round-trips', () {
      const connection = ManualConnection(
        host: '192.168.1.5',
        port: 44353,
        deviceName: "Alex's MacBook",
        deviceId: 'abc123',
        publicKeyHash: 'aBcD1234',
        os: 'macos',
      );
      final uri = connection.toUriString();
      expect(uri, startsWith('aero://connect?'));
      expect(uri, contains('host=192.168.1.5'));
      expect(uri, contains('port=44353'));

      final parsed = parseManualConnection(uri);
      expect(parsed.isSuccess, isTrue);
      final back = parsed.connection!;
      expect(back.host, '192.168.1.5');
      expect(back.port, 44353);
      expect(back.deviceName, "Alex's MacBook", reason: 'percent-encoding round-trips');
      expect(back.deviceId, 'abc123');
      expect(back.publicKeyHash, 'aBcD1234');
      expect(back.os, 'macos');
    });

    test('omits empty optional fields', () {
      const connection = ManualConnection(host: '10.0.0.1', port: 44353);
      final uri = connection.toUriString();
      expect(uri, isNot(contains('name=')));
      expect(uri, isNot(contains('id=')));
    });
  });

  group('parseManualConnection - accepted forms', () {
    test('parses the full aero:// query form', () {
      final r = parseManualConnection(
        'aero://connect?host=192.168.43.1&port=44353&name=Phone&id=xyz&os=android',
      );
      expect(r.isSuccess, isTrue);
      expect(r.connection!.host, '192.168.43.1');
      expect(r.connection!.port, 44353);
      expect(r.connection!.deviceName, 'Phone');
    });

    test('parses a bare host:port', () {
      final r = parseManualConnection('192.168.1.9:44353');
      expect(r.isSuccess, isTrue);
      expect(r.connection!.host, '192.168.1.9');
      expect(r.connection!.port, 44353);
    });

    test('parses a bracketed IPv6 host:port', () {
      final r = parseManualConnection('[2001:db8::1]:44353');
      expect(r.isSuccess, isTrue);
      expect(r.connection!.host, '2001:db8::1');
      expect(r.connection!.port, 44353);
    });

    test('tolerates surrounding whitespace', () {
      final r = parseManualConnection('  192.168.1.9:44353  ');
      expect(r.isSuccess, isTrue);
    });
  });

  group('parseManualConnection - rejections', () {
    test('empty input', () {
      final r = parseManualConnection('   ');
      expect(r.isSuccess, isFalse);
      expect(r.reason, ManualParseFailure.empty);
      expect(r.message, contains('Enter or paste'));
    });

    test('over-long input is refused before parsing', () {
      final r = parseManualConnection('a' * (kMaxManualPayloadLength + 1));
      expect(r.reason, ManualParseFailure.tooLong);
    });

    test('hostname is refused, since DNS may be the broken thing', () {
      final r = parseManualConnection('aero://connect?host=example.local&port=44353');
      expect(r.reason, ManualParseFailure.badAddress);
      expect(r.detail, contains('not an IP address'));
    });

    test('bare hostname is refused', () {
      final r = parseManualConnection('example.local:44353');
      expect(r.reason, ManualParseFailure.badAddress);
    });

    test('loopback is refused - it is not a peer', () {
      final r = parseManualConnection('127.0.0.1:44353');
      expect(r.reason, ManualParseFailure.badAddress);
      expect(r.detail, contains('loopback'));
    });

    test('the wildcard address is refused', () {
      final r = parseManualConnection('0.0.0.0:44353');
      expect(r.reason, ManualParseFailure.badAddress);
    });

    test('missing port', () {
      final r = parseManualConnection('192.168.1.5');
      expect(r.reason, ManualParseFailure.unrecognised);
    });

    test('non-numeric port', () {
      final r = parseManualConnection('192.168.1.5:http');
      expect(r.reason, ManualParseFailure.badPort);
    });

    test('out-of-range port', () {
      expect(parseManualConnection('192.168.1.5:0').reason, ManualParseFailure.badPort);
      expect(parseManualConnection('192.168.1.5:70000').reason, ManualParseFailure.badPort);
    });

    test('an unrelated scheme is not treated as a connection', () {
      final r = parseManualConnection('https://example.com');
      // Falls through to the bare parser, which finds no valid host:port.
      expect(r.isSuccess, isFalse);
    });

    test('every failure reason has a distinct, non-empty id', () {
      final ids = ManualParseFailure.values.map((f) => f.id).toSet();
      expect(ids.length, ManualParseFailure.values.length);
      expect(ids.every((id) => id.isNotEmpty), isTrue);
    });
  });

  group('parsing is hostile-input safe', () {
    test('control and bidi characters are stripped from names', () {
      final r = parseManualConnection(
        'aero://connect?host=192.168.1.5&port=44353&name=bad\u202Ename%07',
      );
      expect(r.isSuccess, isTrue);
      expect(r.connection!.deviceName, isNot(contains('\u202E')));
    });

    test('a name is clipped to 80 runes', () {
      // Sized so the overall URI stays under kMaxManualPayloadLength (a larger
      // string is refused wholesale, which the next test covers), but the name
      // is longer than the 80-rune cap and must be truncated.
      final long = 'x' * 200;
      final r = parseManualConnection(
        'aero://connect?host=192.168.1.5&port=44353&name=$long',
      );
      expect(r.isSuccess, isTrue);
      expect(r.connection!.deviceName.length, 80);
    });

    test('an over-length payload is refused wholesale, not silently truncated', () {
      // A name large enough to push the whole payload past the cap. Refusing is
      // the right behaviour: the string is either corrupt or hostile, and
      // clipping it would mean acting on input we do not understand.
      final long = 'x' * 900;
      final r = parseManualConnection(
        'aero://connect?host=192.168.1.5&port=44353&name=$long',
      );
      expect(r.isSuccess, isFalse);
      expect(r.reason, ManualParseFailure.tooLong);
    });

    test('a path-like host cannot slip through', () {
      final r = parseManualConnection('aero://connect?host=evil.com/x&port=44353');
      expect(r.reason, ManualParseFailure.badAddress);
    });
  });

  group('encode/decode for a future QR renderer', () {
    test('decodes UTF-8 bytes back into a connection', () {
      const connection = ManualConnection(host: '192.168.1.5', port: 44353);
      final bytes = utf8.encode(encodeManualPayload(connection));
      final r = decodeManualPayload(bytes);
      expect(r.isSuccess, isTrue);
      expect(r.connection!.host, '192.168.1.5');
    });

    test('invalid UTF-8 is a clean failure, not a crash', () {
      final r = decodeManualPayload([0xff, 0xfe, 0xfd]);
      expect(r.isSuccess, isFalse);
    });
  });

  group('buildManualConnection', () {
    test('returns a payload when host and port are known', () {
      final c = buildManualConnection(
        host: '192.168.1.5',
        port: 44353,
        deviceName: 'Mac',
        deviceId: 'abc',
        publicKeyHash: 'pk',
        os: 'macos',
      );
      expect(c, isNotNull);
      expect(c!.host, '192.168.1.5');
    });

    test('returns null without a dialable address', () {
      expect(
        buildManualConnection(
          host: null,
          port: 44353,
          deviceName: 'Mac',
          deviceId: 'abc',
          publicKeyHash: '',
          os: 'macos',
        ),
        isNull,
      );
    });

    test('returns null without a port', () {
      expect(
        buildManualConnection(
          host: '192.168.1.5',
          port: null,
          deviceName: 'Mac',
          deviceId: 'abc',
          publicKeyHash: '',
          os: 'macos',
        ),
        isNull,
      );
    });
  });

  group('Phase3LinkStrategy', () {
    NetworkContext ctx(NetworkContextReason reason) =>
        NetworkContext(interfaces: const [], reason: reason);

    test('a usable LAN wins over every fallback', () {
      const s = Phase3LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
      final d = s.select(ctx(NetworkContextReason.lanAvailable));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.lanAvailable);
    });

    test('no subnet + can host selects the hotspot', () {
      const s = Phase3LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
      expect(s.select(ctx(NetworkContextReason.noSharedSubnet)).tier, TransportTier.hotspot);
    });

    test('no subnet + cannot host + BLE selects BLE', () {
      const s = Phase3LinkStrategy(canHostHotspot: false, canBleRendezvous: true);
      expect(
        s.select(ctx(NetworkContextReason.noSharedSubnet)).tier,
        TransportTier.bleRendezvous,
      );
    });

    test('no subnet + cannot host + no BLE selects manual', () {
      const s = Phase3LinkStrategy(canHostHotspot: false, canBleRendezvous: false);
      final d = s.select(ctx(NetworkContextReason.noSharedSubnet));
      expect(d.tier, TransportTier.manual);
      expect(d.reason, TierReason.manualRequired);
      expect(d.detail, contains('connection string'));
    });

    test('the ladder always has a bottom rung', () {
      // Every capability combination must select *something* actionable; the
      // selector can never report "there is nothing we can do".
      for (final host in [true, false]) {
        for (final ble in [true, false]) {
          final s = Phase3LinkStrategy(canHostHotspot: host, canBleRendezvous: ble);
          for (final reason in NetworkContextReason.values) {
            final d = s.select(ctx(reason));
            expect(() => d, returnsNormally);
            expect(d.tier, isNotNull);
          }
        }
      }
    });

    test('never throws for any reason and any capability combination', () {
      for (final host in [true, false]) {
        for (final ble in [true, false]) {
          final s = Phase3LinkStrategy(canHostHotspot: host, canBleRendezvous: ble);
          for (final reason in NetworkContextReason.values) {
            expect(() => s.select(ctx(reason)), returnsNormally);
          }
        }
      }
    });

    test('an unusable interface still waits rather than going manual', () {
      const s = Phase3LinkStrategy(canHostHotspot: false, canBleRendezvous: false);
      final d = s.select(ctx(NetworkContextReason.noUsableInterface));
      expect(d.tier, TransportTier.sharedLan);
      expect(d.reason, TierReason.noUsableInterface);
    });

    test('NO_REACHABLE_PEERS still never selects a fallback', () {
      expect(mdnsUnavailableReason(null, 0), TierReason.noReachablePeers);
      const s = Phase3LinkStrategy(canHostHotspot: true, canBleRendezvous: true);
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

    test('manual does not use the shared-LAN transport', () {
      expect(TransportTier.manual.usesSharedLanTransport, isFalse);
    });
  });

  group('complete tier ladder (Phase 0 -> 3)', () {
    final context = NetworkContext(
      interfaces: const [],
      reason: NetworkContextReason.noSharedSubnet,
    );

    test('all four rungs are reachable', () {
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
      expect(
        const Phase3LinkStrategy(canHostHotspot: false, canBleRendezvous: false)
            .select(context)
            .tier,
        TransportTier.manual,
      );
    });

    test('the ladder ranks are strictly ordered by preference', () {
      expect(TransportTier.sharedLan.rank, lessThan(TransportTier.hotspot.rank));
      expect(TransportTier.hotspot.rank, lessThan(TransportTier.bleRendezvous.rank));
      expect(TransportTier.bleRendezvous.rank, lessThan(TransportTier.manual.rank));
    });
  });
}
