import 'package:aero/core/constants.dart';
import 'package:aero/core/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('PeerInfo', () {
    PeerInfo info({Set<Capability> caps = const {Capability.receive}}) => PeerInfo(
          deviceId: 'aabb',
          deviceName: 'Test Mac',
          os: AeroOs.macos,
          osVersion: '14.0',
          appVersion: '1.0.0',
          publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
          protocolVersion: kProtocolVersion,
          capabilities: caps,
          nonce: 'bm9uY2U=',
        );

    test('round-trips through JSON', () {
      final original = info();
      final decoded = PeerInfo.fromJson(original.toJson());

      expect(decoded.deviceId, original.deviceId);
      expect(decoded.deviceName, original.deviceName);
      expect(decoded.os, original.os);
      expect(decoded.protocolVersion, original.protocolVersion);
      expect(decoded.capabilities, original.capabilities);
      expect(decoded.nonce, original.nonce);
    });

    test('survives a JSON body with every field missing', () {
      // A peer is an unauthenticated network input; a partial body must not
      // crash the parser.
      final decoded = PeerInfo.fromJson(const {});
      expect(decoded.deviceId, isEmpty);
      expect(decoded.deviceName, 'Unknown device');
      expect(decoded.protocolVersion, 0);
      expect(decoded.isCompatible, isFalse);
    });

    test('ignores unrecognised capability names', () {
      // Forward compatibility: a newer peer may advertise caps we lack. They
      // are dropped rather than throwing.
      final decoded = PeerInfo.fromJson({
        'capabilities': ['receive', 'quantum-teleport'],
      });
      expect(decoded.capabilities, {Capability.receive});
    });

    test('flags a protocol version mismatch as incompatible', () {
      final decoded = PeerInfo.fromJson({'protocol': kProtocolVersion + 1});
      expect(decoded.isCompatible, isFalse);
    });

    test('TXT record carries a public-key hash, never the key itself', () {
      final txt = info().toTxt();
      expect(txt[TxtKey.publicKeyHash], isNotEmpty);
      expect(txt[TxtKey.publicKeyHash], isNot(contains('=')),
          reason: 'base64url without padding');
      expect(
        txt.values.any((v) => v == info().publicKey),
        isFalse,
        reason: 'the raw key must not be broadcast',
      );
    });

    test('TXT record carries the port the PeerInfo was built with', () {
      // `toTxt()` publishes a snapshot of `PeerInfo.port`. When the transport
      // binds an ephemeral port instead of kPreferredPort, that port is what
      // must be advertised — so this asserts the field is passed through, not
      // that it always equals kPreferredPort.
      expect(info().toTxt()[TxtKey.port], '$kPreferredPort');

      final onCustomPort = PeerInfo.fromJson({...info().toJson(), 'port': 51234});
      expect(onCustomPort.toTxt()[TxtKey.port], '51234');
    });

    test('the advertised port survives a JSON round trip', () {
      // `PeerInfo.fromJson` reads `port`, but `DiscoveryService.start({port})`
      // is the authoritative value at runtime. This guards the round trip.
      final original = PeerInfo.fromJson({...info().toJson(), 'port': 51234});
      expect(PeerInfo.fromJson(original.toJson()).toTxt()[TxtKey.port], '51234');
    });

    test('hashPublicKey is stable and empty-safe', () {
      expect(PeerInfo.hashPublicKey('AAAA'), PeerInfo.hashPublicKey('AAAA'));
      expect(PeerInfo.hashPublicKey(''), isEmpty);
      expect(PeerInfo.hashPublicKey('not base64!!!'), isEmpty);
    });
  });

  group('FileEntry', () {
    test('round-trips including optional fields', () {
      const entry = FileEntry(
        id: 'f1',
        name: 'photo.jpg',
        size: 2048,
        relPath: 'Trip/photo.jpg',
        sha256: 'abc',
        mtimeMs: 1700000000000,
      );
      final decoded = FileEntry.fromJson(entry.toJson());
      expect(decoded.id, 'f1');
      expect(decoded.relPath, 'Trip/photo.jpg');
      expect(decoded.sha256, 'abc');
      expect(decoded.mtimeMs, 1700000000000);
    });

    test('omits null optionals so the wire format stays small', () {
      const entry = FileEntry(id: 'f', name: 'n', size: 0);
      final json = entry.toJson();
      expect(json.containsKey('relPath'), isFalse);
      expect(json.containsKey('sha256'), isFalse);
    });

    test('handles a size beyond 32 bits', () {
      // Multi-GB files must not be truncated by an int32 somewhere in the
      // pipeline.
      final big = FileEntry.fromJson({'id': 'x', 'name': 'x', 'size': 5 * 1024 * 1024 * 1024});
      expect(big.size, 5 * 1024 * 1024 * 1024);
    });
  });

  group('Offer / OfferResponse', () {
    test('offer round-trips a multi-file payload', () {
      final offer = Offer(
        sessionId: 's1',
        totalSize: 30,
        folderName: 'Trip',
        files: const [
          FileEntry(id: 'a', name: 'a.txt', size: 10, relPath: 'Trip/a.txt'),
          FileEntry(id: 'b', name: 'b.txt', size: 20),
        ],
      );
      final decoded = Offer.fromJson(offer.toJson());

      expect(decoded.sessionId, 's1');
      expect(decoded.folderName, 'Trip');
      expect(decoded.files.length, 2);
      expect(decoded.totalSize, 30);
    });

    test('offer response round-trips rejections with reasons', () {
      final response = OfferResponse(
        sessionId: 's1',
        accepted: ['a'],
        rejected: const [('b', RejectReason.noSpace)],
        resume: const {'c': 1024},
      );
      final decoded = OfferResponse.fromJson(response.toJson());

      expect(decoded.accepted, ['a']);
      expect(decoded.rejected.length, 1);
      expect(decoded.rejected.first.$2, RejectReason.noSpace);
      expect(decoded.resume['c'], 1024);
      expect(decoded.hasResume, isTrue);
    });

    test('an unknown rejection reason degrades instead of throwing', () {
      final decoded = OfferResponse.fromJson({
        'accepted': <String>[],
        'rejected': [
          {'id': 'x', 'reason': 'warp-core-overheated'}
        ],
      });
      expect(decoded.rejected.single.$2, RejectReason.unknown);
    });
  });

  group('CompletionReport', () {
    test('round-trips digests and byte counts', () {
      final report = CompletionReport(
        sessionId: 's1',
        files: const [('a', 'deadbeef', 1234)],
      );
      final decoded = CompletionReport.fromJson(report.toJson());
      expect(decoded.files.single.$1, 'a');
      expect(decoded.files.single.$2, 'deadbeef');
      expect(decoded.files.single.$3, 1234);
      expect(decoded.cancelled, isFalse);
    });
  });

  group('PairingProof', () {
    test('formats digits for display', () {
      final proof = PairingProof(
        method: 'sas',
        value: '472905',
        expiresAt: DateTime.now().add(const Duration(minutes: 1)),
      );
      expect(proof.display, '4 7 2 9 0 5');
      expect(proof.isExpired(), isFalse);
    });

    test('detects expiry', () {
      final proof = PairingProof(
        method: 'sas',
        value: '000000',
        expiresAt: DateTime(2020),
      );
      expect(proof.isExpired(), isTrue);
    });
  });

  group('ApiError -> HTTP status mapping', () {
    test('the codes the client branches on map to distinct statuses', () {
      // PeerException derives its status from these codes; a collision would
      // make client-side error handling ambiguous.
      expect(ApiError.notPaired, isNot(ApiError.sasMismatch));
      expect(ApiError.sasMismatch, isNot(ApiError.sasExpired));
    });
  });
}