/// Real-device discovery test: does one process actually *find* another?
///
/// mDNS cannot be unit tested. bonsoir's Darwin backend reaches mDNSResponder
/// through a real `FlutterMethodChannel`, which only exists inside a running
/// Flutter app, so unit tests can only exercise the pure parsing helpers.
/// Advertising and browsing — the parts that actually break — need the engine:
///
/// ```
/// flutter test integration_test/mdns_discovery_test.dart -d macos
/// ```
///
/// This is self-contained rather than depending on a second app being open: it
/// advertises a fake peer with bonsoir directly, then browses for it with
/// [MdnsDiscovery], with two *different* device ids so the self-filter does not
/// discard it. A running `aero.app` on the same network is picked up as well,
/// which is why the assertions are written as "contains" rather than "equals
/// exactly one".
///
/// Skips instead of failing when the machine legitimately cannot do multicast
/// (locked-down Mac, no local-network permission, no non-loopback interface),
/// because that is an environment fact, not a code defect. The one thing it
/// never tolerates is silence.
library;

import 'dart:async';

import 'package:aero/core/constants.dart';
import 'package:aero/core/discovery/mdns_discovery.dart';
import 'package:aero/core/models.dart';
import 'package:bonsoir/bonsoir.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// The peer we advertise as. Deliberately not the browsing instance's id.
const _peerDeviceId = 'discoverytestpeer0000000000000000';
const _peerName = 'AeroDiscoveryPeer';

/// The browsing instance's own id, so its advertisement (if any) is filtered.
const _selfDeviceId = 'discoverytestself0000000000000000';

PeerInfo _selfInfo() => const PeerInfo(
      deviceId: _selfDeviceId,
      deviceName: 'AeroDiscoverySelf',
      os: AeroOs.macos,
      osVersion: '27',
      appVersion: '1.0.0',
      publicKey: '',
      protocolVersion: kProtocolVersion,
      capabilities: {Capability.receive},
      nonce: '',
      port: kPreferredPort,
    );

BonsoirService _peerService() => BonsoirService(
      name: _peerName,
      type: kServiceType,
      port: 45123,
      attributes: const {
        TxtKey.deviceId: _peerDeviceId,
        TxtKey.deviceName: _peerName,
        TxtKey.os: 'macos',
        TxtKey.osVersion: '27.0',
        TxtKey.appVersion: '1.0.0',
        TxtKey.port: '45123',
        TxtKey.protocol: '1',
        TxtKey.capabilities: 'receive,multiFile,resume',
        // Advertised so the round trip can be asserted. The real app publishes
        // SHA-256 of its Ed25519 public key here, which lets the UI flag a peer
        // whose identity changed *before* the user pairs with it.
        TxtKey.publicKeyHash: 'testpublichash0000000000000000000000000',
      },
    );

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('raw BonsoirBroadcast reaches native and starts', (tester) async {
    // The layer directly beneath MdnsDiscovery. Answers "does the method
    // channel reach mDNSResponder at all?" with printLogs so the native os_log
    // output is visible too.
    final broadcast = BonsoirBroadcast(service: _peerService(), printLogs: false);
    final clock = Stopwatch()..start();
    final events = <String>[];
    final started = Completer<void>();

    await broadcast.initialize();
    debugPrint('RAW initialize() returned at ${clock.elapsedMilliseconds}ms');

    broadcast.eventStream?.listen(
      (event) {
        events.add(event.runtimeType.toString());
        if (event is BonsoirBroadcastStartedEvent && !started.isCompleted) {
          started.complete();
        }
      },
      onError: (Object error) {
        events.add('error:$error');
        debugPrint('RAW stream error: $error');
      },
    );

    var startReturned = false;
    try {
      await broadcast.start().timeout(const Duration(seconds: 10));
      startReturned = true;
    } on TimeoutException {
      debugPrint('RAW start() did not return within 10s');
    }

    await Future.any<void>([
      started.future,
      Future<void>.delayed(const Duration(seconds: 5)),
    ]);
    debugPrint('RAW startReturned=$startReturned events=$events started=${started.isCompleted}');

    // start() must not hang. Whether it *succeeds* is environmental.
    expect(startReturned, isTrue,
        reason: 'BonsoirBroadcast.start() never returned: the native call is '
            'blocking the platform thread rather than reporting a result.');

    await broadcast.stop().catchError((_) {});
  });

  testWidgets('MdnsDiscovery finds an advertised peer', (tester) async {
    // Advertise first so the record exists before browsing starts.
    final broadcast = BonsoirBroadcast(service: _peerService(), printLogs: false);
    await broadcast.initialize();
    final advertiseStarted = Completer<void>();
    broadcast.eventStream?.listen(
      (event) {
        if (event is BonsoirBroadcastStartedEvent && !advertiseStarted.isCompleted) {
          advertiseStarted.complete();
        }
      },
      onError: (Object error) => debugPrint('advertise error: $error'),
    );
    await broadcast.start();
    await Future.any<void>([
      advertiseStarted.future,
      Future<void>.delayed(const Duration(seconds: 6)),
    ]);

    final discovery = MdnsDiscovery();
    addTearDown(() async {
      await discovery.dispose();
      await broadcast.stop().catchError((_) {});
    });

    final found = <DiscoveredPeer>[];
    final foundPeer = Completer<DiscoveredPeer>();
    discovery.peers.listen((p) {
      found.add(p);
      if (p.deviceId == _peerDeviceId && !foundPeer.isCompleted) {
        foundPeer.complete(p);
      }
    });

    await discovery.start(port: kPreferredPort, self: _selfInfo());
    debugPrint('DISCOVERY after start: ${discovery.diagnostics}');

    if (discovery.unavailableReason != null) {
      // A legitimate environment limitation. Report it loudly, do not fail:
      // the point of this test is to catch *silent* failure.
      debugPrint('SKIP REASON: ${discovery.unavailableReason}');
      markTestSkipped('mDNS unavailable in this environment: '
          '${discovery.unavailableReason}');
      return;
    }

    // Give mDNS a generous window. A cold mDNSResponder cache plus the 1s
    // announcement delay means a few seconds is normal, not a problem.
    await Future.any<void>([
      foundPeer.future,
      Future<void>.delayed(const Duration(seconds: 30)),
    ]);

    debugPrint('DISCOVERY after wait: ${discovery.diagnostics}');
    debugPrint('DISCOVERY peers found: '
        '${found.map((p) => '${p.info.deviceName}@${p.address}').toList()}');

    final peer = found.where((p) => p.deviceId == _peerDeviceId).firstOrNull;

    expect(
      peer,
      isNotNull,
      reason: 'The advertised peer was never discovered. This is the real '
          'regression guard: discovery silently produced nothing. '
          'diagnostics=${discovery.diagnostics}',
    );

    // The address must be dialable, not the wildcard or a link-local address.
    expect(peer!.address.host, isNotEmpty);
    expect(peer.address.host, isNot('0.0.0.0'));
    expect(peer.address.host.startsWith('fe80:'), isFalse,
        reason: 'link-local IPv6 needs a scope id and cannot be dialled');
    expect(peer.address.port, 45123);

    // TXT must survive the round trip, since that is how a peer is identified
    // before any connection is made.
    expect(peer.info.deviceName, _peerName);
    expect(peer.info.protocolVersion, kProtocolVersion);
    expect(peer.info.os, AeroOs.macos);
    expect(peer.info.capabilities, contains(Capability.receive));
    expect(peer.info.publicKeyHash, isNotEmpty,
        reason: 'the key hash is what lets the UI flag a changed identity '
            'before pairing');
  });
}
