import 'dart:convert';
import 'dart:io';

import 'package:aero/core/contracts.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('aero_identity_test_');
  });

  tearDown(() async {
    if (await tmp.exists()) await tmp.delete(recursive: true);
  });

  group('Ed25519Identity', () {
    test('deviceId is 32 lowercase hex characters', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      expect(identity.deviceId.length, 32);
      expect(RegExp(r'^[0-9a-f]{32}$').hasMatch(identity.deviceId), isTrue,
          reason: 'got "${identity.deviceId}"');
    });

    test('deviceId is stable across instances sharing a directory', () async {
      final first = await Ed25519Identity.load(directory: tmp);
      final second = await Ed25519Identity.load(directory: tmp);
      expect(second.deviceId, first.deviceId);
      expect(second.publicKey, first.publicKey);
    });

    test('a different directory gets a different identity', () async {
      final other = await Directory.systemTemp.createTemp('aero_identity_b_');
      addTearDown(() async {
        if (await other.exists()) await other.delete(recursive: true);
      });
      final a = await Ed25519Identity.load(directory: tmp);
      final b = await Ed25519Identity.load(directory: other);
      expect(b.deviceId, isNot(a.deviceId));
      expect(b.publicKey, isNot(a.publicKey));
    });

    test('persists to identity.json in the supplied directory', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final file = File('${tmp.path}${Platform.pathSeparator}'
          '${Ed25519Identity.fileName}');
      expect(await file.exists(), isTrue);

      final json = jsonDecode(await file.readAsString())
          as Map<String, dynamic>;
      expect(json['deviceId'], identity.deviceId);
      expect(json['publicKey'], identity.publicKey);
      expect(base64Decode(json['privateKeyB64'] as String), hasLength(32));
      expect(json.containsKey('privateKeyB64'), isTrue);

      // No half-written temporary file may be left behind.
      final leftovers = tmp
          .listSync()
          .whereType<File>()
          .where((f) => f.path.endsWith('.tmp'))
          .toList();
      expect(leftovers, isEmpty);
    });

    test('publicKey decodes to exactly 32 bytes', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      expect(base64Decode(identity.publicKey), hasLength(32));
    });

    test('recovers from a corrupt identity file', () async {
      await File('${tmp.path}${Platform.pathSeparator}'
              '${Ed25519Identity.fileName}')
          .writeAsString('not json at all');
      // Must not throw; a new identity is generated instead.
      final identity = await Ed25519Identity.load(directory: tmp);
      expect(identity.deviceId.length, 32);
      expect(identity.publicKey, isNotEmpty);
    });

    test('refuses a file whose public key contradicts the private key',
        () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final file = File('${tmp.path}${Platform.pathSeparator}'
          '${Ed25519Identity.fileName}');
      final json = jsonDecode(await file.readAsString())
          as Map<String, dynamic>;
      json['publicKey'] = base64.encode(List<int>.filled(32, 0x77));
      await file.writeAsString(jsonEncode(json));

      final reloaded = await Ed25519Identity.load(directory: tmp);
      expect(reloaded.deviceId, isNot(identity.deviceId),
          reason: 'a mismatched pair must be discarded, not adopted');
      // And the reloaded object is self-consistent: it signs with the key it
      // advertises.
      final signature = await reloaded.sign('hello');
      expect(await reloaded.verify('hello', signature), isTrue);
    });
  });

  group('sign / verify', () {
    late Ed25519Identity identity;

    setUp(() async {
      identity = await Ed25519Identity.load(directory: tmp);
    });

    test('round-trips', () async {
      const payload = 'GET /v1/info';
      final signature = await identity.sign(payload);
      expect(base64Decode(signature), hasLength(64));
      expect(await identity.verify(payload, signature), isTrue);
    });

    test('handles multi-line and unicode payloads', () async {
      const payload = 'device: laptop\nname: Café ☕️\ttab';
      final signature = await identity.sign(payload);
      expect(await identity.verify(payload, signature), isTrue);
    });

    test('rejects a tampered payload', () async {
      const payload = 'transfer: offer';
      final signature = await identity.sign(payload);
      expect(await identity.verify('$payload ', signature), isFalse);
    });

    test('rejects a garbage signature without throwing', () async {
      expect(await identity.verify('payload', 'not base64 !!!'), isFalse);
      expect(await identity.verify('payload', ''), isFalse);
      expect(await identity.verify('payload', base64.encode([1, 2, 3])), isFalse);
      expect(
        await identity.verify('payload', base64.encode(List<int>.filled(64, 0))),
        isFalse,
      );
    });

    test('does not verify another device\'s signature', () async {
      final otherDir =
          await Directory.systemTemp.createTemp('aero_identity_other_');
      addTearDown(() async {
        if (await otherDir.exists()) await otherDir.delete(recursive: true);
      });
      final other = await Ed25519Identity.load(directory: otherDir);
      final theirs = await other.sign('payload');
      expect(await identity.verify('payload', theirs), isFalse);
    });

    test('a signature made before a reload still verifies afterwards', () async {
      final signature = await identity.sign('durable');
      final reloaded = await Ed25519Identity.load(directory: tmp);
      expect(await reloaded.verify('durable', signature), isTrue);
    });
  });

  group('freshNonce', () {
    test('differs between calls', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final seen = <String>{};
      for (var i = 0; i < 64; i++) {
        final nonce = identity.freshNonce();
        expect(RegExp(r'^[A-Za-z0-9_-]{22}$').hasMatch(nonce), isTrue,
            reason: 'got "$nonce"');
        expect(seen.add(nonce), isTrue, reason: 'nonce repeated: $nonce');
      }
    });
  });

  group('beginSession', () {
    test('returns non-empty PEM that loads into a real SecurityContext',
        () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final creds = await identity.beginSession();

      expect(creds.certificatePem, contains('BEGIN CERTIFICATE'));
      expect(creds.certificatePem, contains('END CERTIFICATE'));
      expect(creds.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      expect(creds.privateKeyPem, contains('END PRIVATE KEY'));
      expect(creds.certificatePem, isNotEmpty);
      expect(creds.privateKeyPem, isNotEmpty);
      expect(creds.publicKeyB64, isNotEmpty);
      // ECDSA P-256 session keys are 65-byte uncompressed points; only the
      // durable Ed25519 device identity is 32 bytes.
      expect(base64Decode(creds.publicKeyB64), hasLength(65));
      expect(creds.signatureAlgorithm, 'ecdsa-p256');

      // The ground-truth check: dart:io must accept both blobs.
      final ctx = SecurityContext();
      expect(
        () => ctx.useCertificateChainBytes(utf8.encode(creds.certificatePem)),
        returnsNormally,
      );
      expect(
        () => ctx.usePrivateKeyBytes(utf8.encode(creds.privateKeyPem)),
        returnsNormally,
      );
    });

    test('fingerprint is 64 lowercase hex characters', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final creds = await identity.beginSession();
      expect(creds.fingerprintHex.length, 64);
      expect(
        RegExp(r'^[0-9a-f]{64}$').hasMatch(creds.fingerprintHex),
        isTrue,
        reason: 'got "${creds.fingerprintHex}"',
      );
    });

    test('fingerprint is SHA-256 over the DER certificate', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final creds = await identity.beginSession();

      // Decode the PEM body back to DER and hash it independently. This pins
      // the definition down: the fingerprint is over the binary certificate,
      // which is exactly what a TLS peer sees on the wire.
      final der = base64.decode(
        creds.certificatePem
            .split('\n')
            .where((l) => !l.startsWith('-----'))
            .join(),
      );
      expect(der, isNotEmpty);
      final expected = await _sha256Hex(der);
      expect(creds.fingerprintHex, expected);
    });

    test('two sessions give different fingerprints and keys', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      final first = await identity.beginSession();
      final second = await identity.beginSession();

      expect(second.fingerprintHex, isNot(first.fingerprintHex));
      expect(second.certificatePem, isNot(first.certificatePem));
      expect(second.publicKeyB64, isNot(first.publicKeyB64));
    });

    test('is not derived from the long-lived device identity', () async {
      // The device key must never end up in session credentials; that is what
      // "ephemeral" means.
      final identity = await Ed25519Identity.load(directory: tmp);
      final creds = await identity.beginSession();
      expect(creds.publicKeyB64, isNot(identity.publicKey));
    });

    test('many certificates all parse', () async {
      final identity = await Ed25519Identity.load(directory: tmp);
      for (var i = 0; i < 12; i++) {
        final creds = await identity.beginSession();
        final ctx = SecurityContext();
        expect(
          () => ctx.useCertificateChainBytes(utf8.encode(creds.certificatePem)),
          returnsNormally,
          reason: 'iteration $i',
        );
      }
    });
  });

  test('satisfies the frozen interface', () async {
    final identity = await Ed25519Identity.load(directory: tmp);
    final DeviceIdentity contract = identity;
    expect(contract.deviceId, identity.deviceId);
    final SessionCredentials creds = await contract.beginSession();
    expect(creds.fingerprintHex, isNotEmpty);
  });
}

/// SHA-256 as lowercase hex, computed here through `package:cryptography`
/// rather than the app's internal helper. This is not testing SHA-256 — it is
/// pinning down *which bytes* the fingerprint is defined over (the decoded DER
/// certificate), which is the part a future refactor could quietly change.
Future<String> _sha256Hex(List<int> bytes) async {
  final digest = await Sha256().hash(bytes);
  return digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}