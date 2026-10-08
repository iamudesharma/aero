/// Focused tests for the ephemeral ECDSA P-256 session certificate.
///
/// These pin down the properties the rest of the app relies on:
///
///  * the session key is ECDSA P-256 (not Ed25519), because Dart's TLS client
///    refuses Ed25519 certificates;
///  * `fingerprintHex` is SHA-256 over the DER certificate — the pairing code
///    depends on that definition;
///  * the PEM blobs load into a real `dart:io` [SecurityContext];
///  * the DER really carries the P-256 OIDs rather than merely parsing.
///
/// The full TLS handshake is proven by `test/end_to_end_test.dart`.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:aero/core/crypto/ephemeral_certificate.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _derFromPem(String pem) {
  final body = pem
      .split('\n')
      .where((line) => !line.startsWith('-----'))
      .join();
  return base64.decode(body);
}

bool _contains(List<int> haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

Future<String> _sha256Hex(List<int> bytes) async =>
    (await Sha256().hash(bytes))
        .bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

void main() {
  final authority = EphemeralCertAuthority();

  group('EphemeralCertAuthority.issue', () {
    test('emits ECDSA P-256 credentials with a 65-byte uncompressed key',
        () async {
      final creds = await authority.issue();

      expect(creds.signatureAlgorithm, 'ecdsa-p256');
      expect(creds.certificatePem, contains('BEGIN CERTIFICATE'));
      expect(creds.privateKeyPem, contains('BEGIN PRIVATE KEY'));

      final publicKey = base64.decode(creds.publicKeyB64);
      expect(publicKey, hasLength(65));
      expect(publicKey.first, 0x04, reason: 'uncompressed point prefix');
    });

    test('fingerprint is SHA-256 over the DER certificate', () async {
      final creds = await authority.issue();
      final der = _derFromPem(creds.certificatePem);
      expect(creds.fingerprintHex, await _sha256Hex(der));
      expect(RegExp(r'^[0-9a-f]{64}$').hasMatch(creds.fingerprintHex), isTrue);
    });

    test('DER carries the P-256 and ecdsa-with-SHA256 OIDs', () async {
      final der = _derFromPem((await authority.issue()).certificatePem);

      // id-ecPublicKey 1.2.840.10045.2.1
      expect(
        _contains(der, const [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
        isTrue,
        reason: 'id-ecPublicKey missing',
      );
      // prime256v1 1.2.840.10045.3.1.7
      expect(
        _contains(der, const [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        isTrue,
        reason: 'prime256v1 missing',
      );
      // ecdsa-with-SHA256 1.2.840.10045.4.3.2
      expect(
        _contains(der, const [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        isTrue,
        reason: 'ecdsa-with-SHA256 missing',
      );
      expect(utf8.decode(der, allowMalformed: true), contains('aero-ephemeral'));
    });

    test('both PEM blobs load into a real SecurityContext', () async {
      final creds = await authority.issue();
      final context = SecurityContext();
      expect(
        () => context.useCertificateChainBytes(
          utf8.encode(creds.certificatePem),
        ),
        returnsNormally,
      );
      expect(
        () => context.usePrivateKeyBytes(utf8.encode(creds.privateKeyPem)),
        returnsNormally,
      );
    });

    test('many freshly minted certificates all load', () async {
      for (var i = 0; i < 8; i++) {
        final creds = await authority.issue();
        final context = SecurityContext();
        expect(
          () => context.useCertificateChainBytes(
            utf8.encode(creds.certificatePem),
          ),
          returnsNormally,
          reason: 'iteration $i',
        );
        expect(
          () => context.usePrivateKeyBytes(utf8.encode(creds.privateKeyPem)),
          returnsNormally,
          reason: 'iteration $i',
        );
      }
    });

    test('each session is freshly generated', () async {
      final first = await authority.issue();
      final second = await authority.issue();
      expect(second.fingerprintHex, isNot(first.fingerprintHex));
      expect(second.certificatePem, isNot(first.certificatePem));
      expect(second.privateKeyPem, isNot(first.privateKeyPem));
      expect(second.publicKeyB64, isNot(first.publicKeyB64));
    });
  });
}
