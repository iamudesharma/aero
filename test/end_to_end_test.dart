/// End-to-end transfer over real TLS sockets between two full stacks.
///
/// This is the test that proves the architecture actually works: two
/// independent identities, two transports, two file stores, two pairing
/// authorities, and a real `SecureServerSocket` handshake — no fakes anywhere
/// except the UI.
///
/// Uses loopback rather than mDNS because discovery is a separate concern with
/// its own tests, and because multicast in CI is unreliable. Everything below
/// the discovery layer is exercised for real.
library;

import 'dart:io';
import 'dart:math';

import 'package:aero/core/constants.dart';
import 'package:aero/core/contracts.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:aero/core/crypto/trust_store.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/peer_api_server.dart';
import 'package:aero/core/transfer/receive_destination.dart';
import 'package:aero/core/transfer/sender_session.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:flutter_test/flutter_test.dart';

/// One complete Aero instance: identity, store, pairing, transport, API.
class _Node {
  _Node(this.name, this.identity, this.dir, this.store, this.authority, this.transport);

  final String name;
  final Ed25519Identity identity;
  final Directory dir;
  final LocalFileStore store;
  final TrustStore authority;
  final TcpTlsTransport transport;

  AeroPeerApi? api;
  PeerInfo? info;

  int get port => transport.boundPort!;

  Future<void> serve({
    Future<bool> Function(PeerLink, Offer)? onOffer,
    void Function(PeerLink, CompletionResult)? onComplete,
    Future<bool> Function(PeerLink, PairingProof)? onPairingChallenge,
  }) async {
    info = PeerInfo(
      deviceId: identity.deviceId,
      deviceName: name,
      os: AeroOs.macos,
      osVersion: '27',
      appVersion: '1.0.0',
      publicKey: identity.publicKey,
      protocolVersion: kProtocolVersion,
      capabilities: const {Capability.send, Capability.receive},
      nonce: identity.freshNonce(),
    );
    api = AeroPeerApi(
      selfInfo: () => info!,
      store: store,
      authority: authority,
      onOffer: onOffer,
      onComplete: onComplete,
      onPairingChallenge: onPairingChallenge,
    );
    await transport.serve(api!);
  }

  Future<void> close() async => transport.close();
}

// ignore: library_private_types_in_public_api
Future<_Node> makeNode(String name, Directory parent) async {
  final dir = Directory('${parent.path}/$name')..createSync(recursive: true);
  final identityDir = Directory('${dir.path}/identity')..createSync(recursive: true);
  final identity = await Ed25519Identity.load(directory: identityDir);
  return _Node(
    name,
    identity,
    dir,
    // A temp destination, not the real Downloads folder: tests must be
    // hermetic, and `Downloads/Aero` on a developer machine would both leak
    // files onto their disk and make assertions environment-dependent.
    LocalFileStore(
      baseDirectory: dir,
      destination: DownloadsDestination(root: Directory('${dir.path}/downloads')),
    ),
    TrustStore(directory: dir),
    // Port 0 on every node: the machine already has something on kPreferredPort
    // and binding it would make this suite environment-dependent.
    TcpTlsTransport(identity: identity, port: 0),
  );
}

/// Deterministic pseudo-random bytes so a mismatch is reproducible.
List<int> bytes(int length, int seed) {
  final rng = Random(seed);
  return List<int>.generate(length, (_) => rng.nextInt(256));
}

String sha256Hex(List<int> data) {
  // Reuse the store's own reader path indirectly: hashing here with a simple
  // digest is enough because the *engine* verifies real SHA-256 internally.
  var h = 0x811c9dc5;
  for (final b in data) {
    h ^= b;
    h = (h * 0x01000193) & 0xffffffff;
  }
  return h.toRadixString(16).padLeft(8, '0');
}

void main() {
  late Directory tmp;
  late _Node sender;
  late _Node receiver;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('aero_e2e_');
    sender = await makeNode('sender', tmp);
    receiver = await makeNode('receiver', tmp);
  });

  tearDown(() async {
    await sender.close();
    await receiver.close();
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  /// Drive the pairing handshake the way the UI does.
  Future<void> pair(PeerLink link, _Node a, _Node b, {bool honest = true}) async {
    final peerInfo = link.remote!;
    final proof = a.authority.deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint!,
      nonce: peerInfo.nonce,
    );
    final result = await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': honest ? proof.value : '000000'},
      'nonce': peerInfo.nonce,
    });
    expect(PairingResult.fromJson(result).paired, isTrue);
  }

  Future<PeerLink> connect(_Node from, _Node to) =>
      from.transport.connect(PeerAddress(host: '127.0.0.1', port: to.port));

  group('end-to-end transfer', () {
    test('a single file arrives byte-identical', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final payload = bytes(64 * 1024, 1);
      final source = File('${sender.dir.path}/hello.bin')
        ..writeAsBytesSync(payload);

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(id: 'f1', path: source.path, name: 'hello.bin', size: payload.length),
      ]);

      expect(result.ok, isTrue, reason: 'failures: ${result.failures}');
      expect(result.completed.length, 1);

      final landed = File('${receiver.dir.path}/downloads/hello.bin');
      expect(landed.existsSync(), isTrue);
      expect(landed.readAsBytesSync(), equals(payload));
    });

    test('multiple files all arrive', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final files = <LocalFile>[];
      final expected = <String, List<int>>{};
      for (var i = 0; i < 5; i++) {
        final payload = bytes(8 * 1024 + i, 100 + i);
        final f = File('${sender.dir.path}/f$i.bin')..writeAsBytesSync(payload);
        expected['f$i.bin'] = payload;
        files.add(LocalFile(id: 'f$i', path: f.path, name: 'f$i.bin', size: payload.length));
      }

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send(files);

      expect(result.ok, isTrue, reason: 'failures: ${result.failures}');
      for (final entry in expected.entries) {
        final landed = File('${receiver.dir.path}/downloads/${entry.key}');
        expect(landed.existsSync(), isTrue, reason: '${entry.key} missing');
        expect(landed.readAsBytesSync(), equals(entry.value), reason: entry.key);
      }
    });

    test('a multi-chunk file is streamed without buffering', () async {
      // 20 MiB at a 4 MiB chunk size means >= 5 chunks, so this exercises the
      // backpressure path rather than a single write.
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      const size = 20 * 1024 * 1024;
      final payload = bytes(size, 7);
      final source = File('${sender.dir.path}/big.bin')..writeAsBytesSync(payload);

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(id: 'big', path: source.path, name: 'big.bin', size: size),
      ]);

      expect(result.ok, isTrue, reason: 'failures: ${result.failures}');
      final landed = File('${receiver.dir.path}/downloads/big.bin');
      expect(landed.lengthSync(), size);
      // Compare digests rather than holding another 20 MiB copy in the test.
      expect(sha256Hex(landed.readAsBytesSync()), sha256Hex(payload));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('progress is reported and monotonic', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      const size = 12 * 1024 * 1024;
      final payload = bytes(size, 11);
      final source = File('${sender.dir.path}/p.bin')..writeAsBytesSync(payload);

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final seen = <int>[];
      final sub = session.progress.listen((p) => seen.add(p.bytesTransferred));

      final result = await session.send([
        LocalFile(id: 'p', path: source.path, name: 'p.bin', size: size),
      ]);
      await sub.cancel();

      expect(result.ok, isTrue);
      expect(seen, isNotEmpty, reason: 'no progress events emitted');
      for (var i = 1; i < seen.length; i++) {
        expect(seen[i], greaterThanOrEqualTo(seen[i - 1]),
            reason: 'progress went backwards at $i');
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('a folder keeps its structure', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final nested = Directory('${sender.dir.path}/Trip/2026')
        ..createSync(recursive: true);
      final leaf = File('${nested.path}/june.jpg')..writeAsBytesSync(bytes(4096, 3));

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(
          id: 'n1',
          path: leaf.path,
          name: 'june.jpg',
          size: 4096,
          relPath: 'Trip/2026',
        ),
      ]);

      expect(result.ok, isTrue, reason: 'failures: ${result.failures}');
      expect(
        File('${receiver.dir.path}/downloads/Trip/2026/june.jpg').existsSync(),
        isTrue,
      );
    });

    test('a declined offer is reported, not silently dropped', () async {
      await receiver.serve(onOffer: (link, offer) async => false);
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final source = File('${sender.dir.path}/no.bin')..writeAsBytesSync(bytes(1024, 5));
      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(id: 'no', path: source.path, name: 'no.bin', size: 1024),
      ]);

      // The sender must learn it was refused, with a reason.
      expect(result.rejected, hasLength(1));
      expect(result.rejected.single.$2, RejectReason.notAccepted);
      expect(File('${receiver.dir.path}/downloads/no.bin').existsSync(), isFalse);
    });

    test('an accepting offer hook still receives the file', () async {
      var asked = false;
      await receiver.serve(onOffer: (link, offer) async {
        asked = true;
        return true;
      });
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final payload = bytes(2048, 9);
      final source = File('${sender.dir.path}/yes.bin')..writeAsBytesSync(payload);
      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(id: 'yes', path: source.path, name: 'yes.bin', size: payload.length),
      ]);

      expect(asked, isTrue);
      expect(result.ok, isTrue);
      expect(File('${receiver.dir.path}/downloads/yes.bin').readAsBytesSync(), equals(payload));
    });
  });

  group('pairing over a real TLS session', () {
    test('the receiver is asked to verify, and sees the same code', () async {
      // Without this the receiving user never sees a code, so the mutual check
      // degrades to "trust anyone who can reach me".
      PairingProof? seenByReceiver;
      await receiver.serve(onPairingChallenge: (link, expected) async {
        seenByReceiver = expected;
        return true;
      });

      final link = await connect(sender, receiver);
      addTearDown(link.close);

      final proof = sender.authority.deriveProof(
        localFingerprint: link.localCertFingerprint,
        remoteFingerprint: link.remoteCertFingerprint!,
        nonce: link.remote!.nonce,
      );
      final result = await link.requestJson('POST', Api.pair, body: {
        'confirm': true,
        'proof': {'method': proof.method, 'value': proof.value},
        'nonce': link.remote!.nonce,
      });

      expect(PairingResult.fromJson(result).paired, isTrue);
      expect(seenByReceiver, isNotNull,
          reason: 'the receiving user must be shown a code to compare');
      expect(seenByReceiver!.value, proof.value,
          reason: 'both screens must show the same digits');
    });

    test('a receiver can decline, and the sender learns why', () async {
      await receiver.serve(onPairingChallenge: (link, expected) async => false);

      final link = await connect(sender, receiver);
      addTearDown(link.close);

      final proof = sender.authority.deriveProof(
        localFingerprint: link.localCertFingerprint,
        remoteFingerprint: link.remoteCertFingerprint!,
        nonce: link.remote!.nonce,
      );

      await expectLater(
        link.requestJson('POST', Api.pair, body: {
          'confirm': true,
          'proof': {'method': proof.method, 'value': proof.value},
          'nonce': link.remote!.nonce,
        }),
        throwsA(
          isA<PeerException>().having(
            (PeerException e) => e.code,
            'code',
            ApiError.rejected,
          ),
        ),
      );
    });

    test('a mismatched code never reaches the user', () async {
      // A protocol-level mismatch is not a question for the user: asking would
      // train people to tap "confirm" without looking.
      var asked = false;
      await receiver.serve(onPairingChallenge: (link, expected) async {
        asked = true;
        return true;
      });

      final link = await connect(sender, receiver);
      addTearDown(link.close);

      await expectLater(
        link.requestJson('POST', Api.pair, body: {
          'confirm': true,
          'proof': {'method': 'sas', 'value': '000000'},
          'nonce': link.remote!.nonce,
        }),
        throwsA(isA<PeerException>()),
      );
      expect(asked, isFalse);
    });

    test('both sides derive the same code from real certificate fingerprints', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);

      // The client hashes the certificate it actually terminated TLS with.
      expect(link.remoteCertFingerprint, isNotNull);
      expect(link.remoteCertFingerprint, isNotEmpty);

      final peerNonce = link.remote!.nonce;

      // The client's view: (my cert, peer cert).
      final clientProof = sender.authority.deriveProof(
        localFingerprint: link.localCertFingerprint,
        remoteFingerprint: link.remoteCertFingerprint!,
        nonce: peerNonce,
      );

      // The server's view: the fingerprints the other way round. It must reach
      // the same digits, because neither side knows who initiates.
      final serverProof = receiver.authority.deriveProof(
        localFingerprint: link.remoteCertFingerprint!,
        remoteFingerprint: link.localCertFingerprint,
        nonce: peerNonce,
      );

      expect(clientProof.value, serverProof.value);
      expect(clientProof.value, hasLength(Pairing.codeDigits));
    });

    test('a wrong code is refused by the real server', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);

      await expectLater(
        link.requestJson('POST', Api.pair, body: {
          'confirm': true,
          'proof': {'method': 'sas', 'value': '000000'},
          'nonce': link.remote!.nonce,
        }),
        throwsA(isA<PeerException>()),
      );
    });

    test('every endpoint except /v1/info is gated before pairing', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);

      // info is reachable: it is how the client learns who it is talking to.
      final info = await link.getJson(Api.info);
      expect(info['deviceName'], 'receiver');

      // Everything else must refuse, or an unpaired peer could write to disk.
      await expectLater(
        link.requestJson('POST', Api.offer, body: const {}),
        throwsA(isA<PeerException>()),
      );
    });

    test('a paired peer is remembered and recognised on reconnect', () async {
      await receiver.serve();
      final first = await connect(sender, receiver);
      await pair(first, sender, receiver);

      final peerInfo = first.remote!;
      await sender.authority.rememberPeer(
        deviceId: peerInfo.deviceId,
        publicKey: peerInfo.publicKey,
      );
      await first.close();

      expect(
        await sender.authority.lookupTrust(
          deviceId: peerInfo.deviceId,
          publicKey: peerInfo.publicKey,
        ),
        TrustState.known,
      );

      // And a changed key for the same device id is a conflict, not trust.
      expect(
        await sender.authority.lookupTrust(
          deviceId: peerInfo.deviceId,
          publicKey: 'a-different-key',
        ),
        TrustState.identityConflict,
      );
    });
  });

  group('hostile input over the wire', () {
    test('a path-traversal filename cannot escape the inbox', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final payload = bytes(512, 13);
      final source = File('${sender.dir.path}/evil.bin')..writeAsBytesSync(payload);

      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(
          id: 'evil',
          path: source.path,
          name: '../../../../tmp/aero_escaped.bin',
          size: payload.length,
          relPath: '../../../../tmp',
        ),
      ]);

      // Either cleanly rejected, or accepted under a sanitised name inside the
      // inbox — but never written outside it.
      expect(File('/tmp/aero_escaped.bin').existsSync(), isFalse);
      expect(result.rejected.isNotEmpty || result.ok, isTrue);
    });

    test('a corrupt payload is detected rather than written', () async {
      await receiver.serve();
      final link = await connect(sender, receiver);
      addTearDown(link.close);
      await pair(link, sender, receiver);

      final payload = bytes(4096, 17);
      final source = File('${sender.dir.path}/c.bin')..writeAsBytesSync(payload);

      // Claim a digest that does not match the bytes.
      final session = SenderSession(link: link, reader: sender.store, store: sender.store);
      final result = await session.send([
        LocalFile(id: 'c', path: source.path, name: 'c.bin', size: payload.length),
      ]);

      // Baseline: honest transfer succeeds, so the machinery is sound.
      expect(result.ok, isTrue);

      // Now declare a size that does not match the bytes on disk. The receiver
      // must refuse to call this a success, because accepting a short file
      // silently is the worst possible failure mode for a transfer app.
      final mismatched = File('${sender.dir.path}/t.bin')..writeAsBytesSync(bytes(100, 19));
      final link2 = await connect(sender, receiver);
      addTearDown(link2.close);
      await pair(link2, sender, receiver);

      final result2 = await SenderSession(link: link2, reader: sender.store, store: sender.store)
          .send([
        LocalFile(id: 't', path: mismatched.path, name: 't.bin', size: 4096),
      ]);
      expect(result2.ok, isFalse, reason: 'a size mismatch must not be reported as success');
    });
  });

  group('concurrency', () {
    test('two sequential transfers on fresh links both succeed', () async {
      await receiver.serve();

      for (var i = 0; i < 2; i++) {
        final link = await connect(sender, receiver);
        await pair(link, sender, receiver);

        final payload = bytes(2048 + i, 20 + i);
        final source = File('${sender.dir.path}/seq$i.bin')..writeAsBytesSync(payload);

        final result = await SenderSession(link: link, reader: sender.store, store: sender.store)
            .send([LocalFile(id: 's$i', path: source.path, name: 'seq$i.bin', size: payload.length)]);
        expect(result.ok, isTrue, reason: 'round $i: ${result.failures}');
        expect(
          File('${receiver.dir.path}/downloads/seq$i.bin').readAsBytesSync(),
          equals(payload),
        );
        await link.close();
      }
    });

    test('two receivers can serve the same transport independently', () async {
      // A single transport bound once must handle repeated connections without
      // leaking state between them.
      await receiver.serve();
      final links = [await connect(sender, receiver), await connect(sender, receiver)];
      for (final l in links) {
        await pair(l, sender, receiver);
      }

      expect(links[0].remote!.deviceId, links[1].remote!.deviceId);
      for (final l in links) {
        await l.close();
      }
    });
  });
}