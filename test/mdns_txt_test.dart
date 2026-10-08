import 'dart:io';

import 'package:aero/core/constants.dart';
import 'package:aero/core/discovery/mdns_discovery.dart';
import 'package:aero/core/models.dart';
import 'package:flutter_test/flutter_test.dart';

/// Every case here is pure: no multicast, no bonsoir instance, no timers. mDNS
/// behaviour that needs real traffic cannot be unit tested without hanging, so
/// what is tested is the part that turns untrusted bytes into a `DiscoveredPeer`.
void main() {
  InternetAddress v4(String literal) => InternetAddress(literal);
  InternetAddress v6(String literal) => InternetAddress(literal);

  Map<String, String> txt({
    String id = 'a1b2c3',
    String name = "Alex's MacBook",
    String os = 'macos',
    String osv = '14.4',
    String app = '1.0.0',
    String port = '44353',
    String proto = '1',
    String caps = 'receive,multiFile',
    String pk = 'aBcD1234',
  }) =>
      <String, String>{
        TxtKey.deviceId: id,
        TxtKey.deviceName: name,
        TxtKey.os: os,
        TxtKey.osVersion: osv,
        TxtKey.appVersion: app,
        TxtKey.port: port,
        TxtKey.protocol: proto,
        TxtKey.capabilities: caps,
        TxtKey.publicKeyHash: pk,
      };

  group('parseResolvedService', () {
    test('turns a well-formed record into a peer', () {
      final peer = parseResolvedService(
        txt(),
        [v4('192.168.1.42')],
        'my-own-id',
      );

      expect(peer, isNotNull);
      final info = peer!.info;
      expect(info.deviceId, 'a1b2c3');
      expect(info.deviceName, "Alex's MacBook");
      expect(info.os, AeroOs.macos);
      expect(info.osVersion, '14.4');
      expect(info.appVersion, '1.0.0');
      expect(info.port, 44353);
      expect(info.protocolVersion, kProtocolVersion);
      expect(info.isCompatible, isTrue);
      expect(info.capabilities, {Capability.receive, Capability.multiFile});
      expect(peer.address.host, '192.168.1.42');
      expect(peer.address.port, 44353);
      expect(peer.deviceId, 'a1b2c3');
    });

    test('address and info stay consistent when the port is overridden', () {
      // PeerAddress and PeerInfo.port must not disagree, or the UI would dial one
      // port while the transfer layer used another.
      final peer = parseResolvedService(
        txt(port: '5000'),
        [v4('10.0.0.9')],
        'self',
      )!;
      expect(peer.address.port, 5000);
      expect(peer.info.port, 5000);
      expect(peer.address.uri.port, 5000);
      expect(peer.address.uri.host, '10.0.0.9');
    });

    test('never carries a public key or nonce from the TXT record', () {
      // Those must come from GET /v1/info over the authenticated channel. A peer
      // that could choose its own key would defeat pairing entirely.
      final info = parseResolvedService(txt(pk: 'whatever-they-like'), [v4('192.168.1.5')], 'self')!.info;
      expect(info.publicKey, isEmpty);
      expect(info.nonce, isEmpty);
      expect(info.trustState, TrustState.unknown);
    });

    test('carries the key *hash* through, which is not a key', () {
      // The hash is the only pre-pairing handle on a peer's identity. It is
      // untrusted, but it is what lets the UI warn that a previously paired
      // device is now presenting a different key, before any code is compared.
      final info = parseResolvedService(
        txt(pk: 'aBcD1234'),
        [v4('192.168.1.5')],
        'self',
      )!.info;
      expect(info.publicKeyHash, 'aBcD1234');
      expect(info.publicKey, isEmpty);
    });

    test('a missing key hash is empty rather than an error', () {
      // Peers that predate the field, or a hostile peer omitting it, must still
      // appear in the list.
      final attrs = Map<String, String>.from(txt())..remove(TxtKey.publicKeyHash);
      final info = parseResolvedService(attrs, [v4('192.168.1.5')], 'self')!.info;
      expect(info.publicKeyHash, isEmpty);
      expect(info.deviceId, 'a1b2c3');
    });

    test('a hostile key hash is length-capped', () {
      final info = parseResolvedService(
        txt(pk: 'A' * 5000),
        [v4('192.168.1.5')],
        'self',
      )!.info;
      expect(info.publicKeyHash.length, lessThan(5000));
    });

    test('leaves a stale-protocol peer visible but flagged', () {
      final peer = parseResolvedService(
        txt(proto: '${kProtocolVersion + 1}'),
        [v4('192.168.1.7')],
        'self',
      )!;
      expect(peer.info.protocolVersion, kProtocolVersion + 1);
      expect(peer.info.isCompatible, isFalse);
    });

    test('drops our own advertisement', () {
      // mDNS responders always see themselves; without this the user pairs with
      // their own machine.
      expect(parseResolvedService(txt(id: 'my-own-id'), [v4('192.168.1.9')], 'my-own-id'), isNull);
    });

    test('drops a record with no device id', () {
      // We could not deduplicate it, could not recognise our own echo, and could
      // never pin its key, so it is not a peer we can act on.
      expect(parseResolvedService(txt(id: ''), [v4('192.168.1.9')], 'self'), isNull);
      expect(parseResolvedService(<String, String>{}, [v4('192.168.1.9')], 'self'), isNull);
      expect(parseResolvedService(txt(id: '   '), [v4('192.168.1.9')], 'self'), isNull);
      expect(parseResolvedService(txt(id: '\u0000\u0007'), [v4('192.168.1.9')], 'self'), isNull);
    });

    test('drops a record whose id differs from ours only by unprintable noise', () {
      // Sanitising both sides keeps the self-filter from being bypassed by
      // padding our own id with control characters.
      expect(parseResolvedService(txt(id: 'me\u0000'), [v4('192.168.1.9')], 'me'), isNull);
      expect(parseResolvedService(txt(id: 'me'), [v4('192.168.1.9')], 'me\u0000'), isNull);
    });

    test('falls back to kPreferredPort for an unusable port', () {
      for (final bad in ['not-a-number', '0', '-1', '65536', '99999999999999999999', '', ' ']) {
        final peer = parseResolvedService(txt(port: bad), [v4('192.168.1.3')], 'self');
        expect(peer, isNotNull, reason: 'port "$bad" should not throw');
        expect(peer!.info.port, kPreferredPort, reason: 'port "$bad"');
        expect(peer.address.port, kPreferredPort, reason: 'port "$bad"');
      }
    });

    test('falls back to the SRV port when the TXT port is missing', () {
      // Bonsoir's SRV port is the one a connection actually lands on, so it beats
      // the "no idea" default when the peer omitted its TXT value.
      final attributes = txt()..remove(TxtKey.port);
      final peer = parseResolvedService(attributes, [v4('192.168.1.3')], 'self', servicePort: 49152)!;
      expect(peer.info.port, 49152);
    });

    test('keeps the TXT port even when the SRV record disagrees', () {
      // The rest of the protocol is written against the advertised port, and the
      // divergence is logged as a warning rather than silently acted on.
      final peer = parseResolvedService(txt(port: '50000'), [v4('192.168.1.3')], 'self', servicePort: 1234)!;
      expect(peer.info.port, 50000);
    });

    test('strips control characters and bidi overrides from the name', () {
      // U+202E reverses the rest of the string when rendered, so a peer could
      // otherwise make its name read as something it is not.
      final peer = parseResolvedService(
        txt(name: 'Ev\u202Eexe.dmg\u0007'),
        [v4('192.168.1.3')],
        'self',
      )!;
      expect(peer.info.deviceName, 'Evexe.dmg');
    });

    test('truncates an overlong name instead of rendering a wall of text', () {
      final peer = parseResolvedService(txt(name: 'x' * 500), [v4('192.168.1.3')], 'self')!;
      expect(peer.info.deviceName.length, kMaxDeviceNameRunes);
    });

    test('truncates on a rune boundary so the name stays encodable', () {
      // 100 astral-plane runes: a naive substring would leave a lone surrogate,
      // which dart:convert then refuses to encode for the wire.
      final peer = parseResolvedService(txt(name: '\u{1F600}' * 100), [v4('192.168.1.3')], 'self')!;
      expect(peer.info.deviceName.runes.length, lessThanOrEqualTo(kMaxDeviceNameRunes));
      expect(peer.info.deviceName.runes.every((r) => r != 0xD83D), isTrue);
    });

    test('substitutes a placeholder for a name that sanitises to nothing', () {
      expect(parseResolvedService(txt(name: '\u0000'), [v4('192.168.1.3')], 'self')!.info.deviceName, kUnknownDeviceName);
      expect(parseResolvedService(txt(name: ''), [v4('192.168.1.3')], 'self')!.info.deviceName, kUnknownDeviceName);
      expect(parseResolvedService(txt(name: '   \t\n'), [v4('192.168.1.3')], 'self')!.info.deviceName, kUnknownDeviceName);
    });

    test('collapses runaway whitespace in the name', () {
      final peer = parseResolvedService(txt(name: '  my    desk \n mac  '), [v4('192.168.1.3')], 'self')!;
      expect(peer.info.deviceName, 'my desk mac');
    });

    test('caps the device id length', () {
      final peer = parseResolvedService(txt(id: 'a' * 4000), [v4('192.168.1.3')], 'self')!;
      expect(peer.info.deviceId.length, kMaxDeviceIdRunes);
    });

    test('an unknown os degrades to unknown rather than throwing', () {
      expect(parseResolvedService(txt(os: 'haiku'), [v4('192.168.1.3')], 'self')!.info.os, AeroOs.unknown);
      expect(parseResolvedService(txt(os: ''), [v4('192.168.1.3')], 'self')!.info.os, AeroOs.unknown);
      expect(parseResolvedService(txt(os: 'MACOS'), [v4('192.168.1.3')], 'self')!.info.os, AeroOs.macos);
    });

    test('a garbage protocol version is incompatible, not accidentally current', () {
      for (final bad in ['nope', '', '-1', '100000']) {
        final info = parseResolvedService(txt(proto: bad), [v4('192.168.1.3')], 'self')!.info;
        expect(info.protocolVersion, 0, reason: 'proto "$bad"');
        expect(info.isCompatible, isFalse, reason: 'proto "$bad"');
      }
    });

    test('ignores capability names it does not know', () {
      final info = parseResolvedService(txt(caps: 'receive,quantum-teleport'), [v4('192.168.1.3')], 'self')!.info;
      expect(info.capabilities, {Capability.receive});
    });

    test('returns null when there are no addresses at all', () {
      expect(parseResolvedService(txt(), const <InternetAddress>[], 'self'), isNull);
    });
  });

  group('address selection', () {
    test('prefers IPv4 and skips IPv6 link-local', () {
      // fe80::/10 needs a scope id that PeerAddress cannot carry, and it arrives
      // first often enough on Linux/Avahi that the order matters.
      expect(
        selectHostAddress([v6('fe80::1c2b:3d4e:5f60:7a8b'), v4('192.168.1.31')])?.address,
        '192.168.1.31',
      );
    });

    test('prefers IPv4 even when it comes last', () {
      expect(
        selectHostAddress([v6('2001:db8::42'), v6('fd00::7'), v4('10.0.0.8')])?.address,
        '10.0.0.8',
      );
    });

    test('falls back to a global IPv6 address', () {
      expect(selectHostAddress([v6('2001:db8::42')])?.address, '2001:db8::42');
      expect(selectHostAddress([v6('fd12:3456::1')])?.address, 'fd12:3456::1');
    });

    test('returns null when the only IPv6 offered is link-local', () {
      expect(selectHostAddress([v6('fe80::1')]), isNull);
    });

    test('skips the wildcard, loopback, and IPv4 link-local', () {
      // A wildcard means "I have no address"; loopback would dial ourselves.
      expect(isDialableHostAddress(v4('0.0.0.0')), isFalse);
      expect(isDialableHostAddress(v4('127.0.0.1')), isFalse);
      expect(isDialableHostAddress(v4('127.13.7.2')), isFalse);
      expect(isDialableHostAddress(v4('169.254.10.1')), isFalse);
      expect(isDialableHostAddress(v6('::')), isFalse);
      expect(isDialableHostAddress(v6('::1')), isFalse);
      expect(isDialableHostAddress(v6('ff02::1')), isFalse);
      expect(isDialableHostAddress(v4('224.0.0.251')), isFalse);
      expect(isDialableHostAddress(v4('192.168.1.4')), isTrue);
    });

    test('skips unusable addresses while looking for one that works', () {
      expect(
        selectHostAddress([v4('0.0.0.0'), v4('127.0.0.1'), v6('fe80::5'), v4('172.20.4.6')])?.address,
        '172.20.4.6',
      );
    });

    test('emits exactly one peer for a dual-stack service', () {
      // One peer per service, one address per peer: a dual-stack peer must not
      // show up three times in the UI.
      final peer = parseResolvedService(
        txt(),
        [v4('192.168.1.11'), v6('fe80::9'), v6('2001:db8::1')],
        'self',
      )!;
      expect(peer.address.host, '192.168.1.11');
    });

    test('rejects a peer that resolved to only unusable addresses', () {
      expect(
        parseResolvedService(txt(), [v4('0.0.0.0'), v4('127.0.0.1'), v6('fe80::1')], 'self'),
        isNull,
      );
    });

    test('an IPv6 host is bracketed by PeerAddress.uri', () {
      // PeerAddress owns the URI rules; all we owe it is a bare literal with no
      // brackets and no zone id.
      final peer = parseResolvedService(txt(), [v6('2001:db8::42')], 'self')!;
      expect(peer.address.host, '2001:db8::42');
      expect(peer.address.uri.toString(), 'aero://[2001:db8::42]:44353');
    });
  });

  group('sanitisation helpers', () {
    test('sanitizeDeviceName caps length and strips controls', () {
      expect(sanitizeDeviceName('a\u0000b'), 'ab');
      expect(sanitizeDeviceName('pad\u202Epad').contains('\u202E'), isFalse);
      expect(sanitizeDeviceName('x' * 300).length, kMaxDeviceNameRunes);
      expect(sanitizeDeviceName(''), kUnknownDeviceName);
    });

    test('sanitizeDeviceName keeps the byte cap below the TXT record limit', () {
      // Each rune is 4 bytes, so 80 runes is 320 bytes - more than a TXT string
      // may carry, which is what the byte cap is for.
      final name = sanitizeDeviceName('\u{1F600}' * 200);
      expect(name.runes.length, lessThanOrEqualTo(kMaxDeviceNameRunes));
      // Every remaining rune costs 4 UTF-8 bytes, so the byte cap is what has to
      // bind here - which is exactly why it exists.
      expect(name.runes.length * 4, lessThanOrEqualTo(kMaxDeviceNameBytes));
    });

    test('sanitizeServiceName honours the 63-byte instance-name limit', () {
      expect(sanitizeServiceName('x' * 200).length, kMaxServiceNameBytes);
      expect(sanitizeServiceName('\u{1F600}' * 100).runes.length, lessThan(kMaxServiceNameRunes + 1));
      expect(sanitizeServiceName('name.'), 'name');
      expect(sanitizeServiceName('   '), kFallbackServiceName);
      expect(sanitizeServiceName('café'), 'café');
    });

    test('sanitizeServiceName can fold to ASCII for the retry attempt', () {
      final folded = sanitizeServiceName('Bücher Büro', asciiOnly: true);
      expect(folded, isNot(contains(RegExp(r'[^\x20-\x7E]'))));
      expect(folded, contains('B'));
      expect(folded, contains('cher'));
    });

    test('parseAdvertisedPort falls back in the documented order', () {
      expect(parseAdvertisedPort('8080'), 8080);
      expect(parseAdvertisedPort(' 8080 '), 8080);
      expect(parseAdvertisedPort('0'), kPreferredPort);
      expect(parseAdvertisedPort('70000'), kPreferredPort);
      expect(parseAdvertisedPort(null), kPreferredPort);
      expect(parseAdvertisedPort('nope', fallback: 4444), 4444);
      expect(parseAdvertisedPort('nope', fallback: 0), kPreferredPort);
      expect(parseAdvertisedPort('44353', fallback: 4444), 44353);
    });

    test('parseCapabilities ignores unknown and junk tokens', () {
      expect(parseCapabilities(null), isEmpty);
      expect(parseCapabilities(''), isEmpty);
      expect(parseCapabilities(',,,'), isEmpty);
      expect(parseCapabilities('send, receive ,resume'), {Capability.send, Capability.receive, Capability.resume});
      expect(parseCapabilities('SEND'), isEmpty);
      expect(parseCapabilities('x' * 4000).length, lessThanOrEqualTo(kMaxCapabilities));
    });

    test('truncateRunes and truncateUtf8 never split a rune', () {
      expect(truncateRunes('abcdef', 3), 'abc');
      expect(truncateRunes('', 3), '');
      expect(truncateRunes('abc', 0), '');
      expect(truncateUtf8('\u{1F600}\u{1F600}', 5), '\u{1F600}');
      expect(truncateUtf8('abc', 0), '');
      expect(truncateUtf8('abc', 99), 'abc');
    });

    test('an overlong hostile id cannot blow up the reported capabilities', () {
      final info = parseResolvedService(
        txt(id: 'z' * 5000, caps: List.filled(500, 'send').join(',')),
        [v4('192.168.1.2')],
        'self',
      )!.info;
      expect(info.deviceId.length, kMaxDeviceIdRunes);
      expect(info.capabilities.length, lessThanOrEqualTo(kMaxCapabilities));
    });
  });

  group('DiscoveryService surface', () {
    test('the backend identifies itself', () {
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      expect(discovery.backendName, 'mdns (bonsoir)');
    });

    test('nothing is unavailable before start', () {
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      expect(discovery.unavailableReason, isNull);
    });

    test('peers is a broadcast stream that tolerates no listeners', () {
      // Broadcast, not single-subscription: the UI, a diagnostics panel and a
      // background refresh all want to watch at once, and nobody may be watching.
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      expect(discovery.peers.isBroadcast, isTrue);
    });

    test('stop is idempotent and safe before start', () async {
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      await discovery.stop();
      await discovery.stop();
      expect(discovery.unavailableReason, isNull);
    });

    test('dispose is idempotent', () async {
      final discovery = MdnsDiscovery();
      await discovery.dispose();
      await discovery.dispose();
    });

    test('diagnostics explains itself before anything has run', () {
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      final diagnostics = discovery.diagnostics;
      expect(diagnostics['backend'], 'mdns (bonsoir)');
      expect(diagnostics['serviceType'], kServiceType);
      // The macOS trap: a missing NSLocalNetworkUsageDescription fails silently,
      // so the counters have to exist and read as "nothing yet".
      expect(diagnostics['unavailableReason'], 'none');
      expect(diagnostics['peersEmitted'], '0');
      expect(diagnostics['servicesSeen'], '0');
      expect(diagnostics['lastError'], 'none');
      expect(diagnostics.containsKey('hint'), isFalse);
    });

    test('using a disposed backend is a programming error, not a crash', () async {
      final discovery = MdnsDiscovery();
      await discovery.dispose();
      expect(
        () => discovery.start(port: kPreferredPort, self: _selfInfo()),
        throwsStateError,
      );
      await expectLater(
        discovery.updateAdvertisedPort(1234),
        throwsStateError,
      );
    });

    test('updateAdvertisedPort before start only records the port', () async {
      // Nothing is advertising yet, so there is nothing to re-register; the value
      // is picked up by start().
      final discovery = MdnsDiscovery();
      addTearDown(discovery.dispose);
      await discovery.updateAdvertisedPort(54321);
      expect(discovery.diagnostics['advertisedPort'], '54321');
      expect(discovery.unavailableReason, isNull);
    });
  });
}

PeerInfo _selfInfo() => PeerInfo(
      deviceId: 'self-device-id',
      deviceName: 'Test Device',
      os: AeroOs.macos,
      osVersion: '14.0',
      appVersion: '1.0.0',
      publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      protocolVersion: kProtocolVersion,
      capabilities: const {Capability.send, Capability.receive},
      nonce: 'bm9uY2U=',
    );