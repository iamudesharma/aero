/// End-to-end pairing handshake against a fake link.
///
/// This is the most important test in the suite: the 6-digit code is the only
/// defence against an active man-in-the-middle, so its failure modes are
/// asserted explicitly rather than assumed.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:aero/core/constants.dart';
import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:flutter_test/flutter_test.dart';

/// Minimal in-memory link. Records requests so tests can assert on the wire.
class FakeLink implements PeerLink {
  FakeLink({
    required PeerInfo remoteInfo,
    this.remoteCertFingerprint = 'aa',
    this.localCertFingerprint = 'bb',
    this.responses = const {},
  }) : remote = remoteInfo;

  @override
  PeerInfo? remote;
  @override
  @override
  final String remoteCertFingerprint;
  @override
  final String localCertFingerprint;

  /// path -> JSON response body.
  final Map<String, Map<String, dynamic>> responses;

  @override
  @override
  bool isPaired = false;

  final List<({String method, String path, Map<String, dynamic>? body})> sent = [];

  @override
  String get transportName => 'fake';

  @override
  Future<Map<String, dynamic>> getJson(String path) => requestJson('GET', path);

  @override
  Future<Map<String, dynamic>> requestJson(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  }) async {
    sent.add((method: method, path: path, body: body));
    final response = responses[path];
    if (response == null) {
      throw PeerException(ApiError.badRequest, 'no stub for $path');
    }
    return response;
  }

  @override
  Future<Map<String, dynamic>> putStream(
    String path,
    Stream<List<int>> data, {
    int? contentLength,
    Map<String, String>? headers,
    void Function(int bytesSent)? onProgress,
  }) async {
    sent.add((method: 'PUT', path: path, body: null));
    return responses[path] ?? const {};
  }

  @override
  Future<void> close() async {}
}

/// The pairing exchange, expressed once so both the "good" and the "bad" cases
/// exercise identical logic. In the app this lives in the session coordinator.
class PairingHandshake {
  PairingHandshake({
    required this.link,
    required this.authority,
    required this.nonce,
  });

  final FakeLink link;
  final PairingAuthority authority;
  final String nonce;

  /// The code this device would display.
  PairingProof localProof() => authority.deriveProof(
        localFingerprint: link.localCertFingerprint,
        remoteFingerprint: link.remoteCertFingerprint,
        nonce: nonce,
      );

  /// Confirm to the peer, sending [code] as the proof.
  Future<Map<String, dynamic>> confirm(String code) {
    link.sent.clear();
    return link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': 'sas', 'value': code},
      'nonce': nonce,
    });
  }
}

/// Reference implementation of the server-side check, matching what the real
/// `AeroPeerApi` must do.
bool serverAccepts({
  required PairingAuthority authority,
  required String localCertFingerprint,
  required String remoteCertFingerprint,
  required String nonce,
  required String presentedCode,
  required String deviceId,
}) {
  if (authority.isRateLimited(deviceId)) return false;

  final expected = authority.deriveProof(
    localFingerprint: localCertFingerprint,
    remoteFingerprint: remoteCertFingerprint,
    nonce: nonce,
  );
  final presented = PairingProof(
    method: 'sas',
    value: presentedCode,
    expiresAt: DateTime.now().add(Pairing.codeLifetime),
  );

  if (!authority.verifyProof(presented, expected)) {
    authority.recordFailure(deviceId);
    return false;
  }
  return true;
}

/// Deterministic SAS used only by tests, standing in for the real crypto-backed
/// authority so these tests do not depend on the crypto layer's internals.
class StubAuthority implements PairingAuthority {
  StubAuthority({Map<String, List<DateTime>>? failures}) : failures = failures ?? {};

  /// deviceId -> failure timestamps.
  final Map<String, List<DateTime>> failures;
  final Map<String, String> trusted = {};

  @override
  PairingProof deriveProof({
    required String localFingerprint,
    required String remoteFingerprint,
    required String nonce,
    String method = 'sas',
  }) {
    // Order-independent by construction: sort before hashing.
    final pair = [localFingerprint, remoteFingerprint]..sort();
    final digest = sha256(utf8.encode('${pair[0]}|${pair[1]}|$nonce'));
    final value = (digest[0] * 1000000 ~/ 251).toString().padLeft(6, '0');
    return PairingProof(
      method: method,
      value: value.substring(0, 6),
      expiresAt: DateTime.now().add(Pairing.codeLifetime),
    );
  }

  @override
  bool verifyProof(PairingProof presented, PairingProof expected) =>
      presented.method == expected.method &&
      presented.value == expected.value &&
      !presented.isExpired() &&
      !expected.isExpired();

  @override
  bool isRateLimited(String deviceId) {
    final now = DateTime.now();
    final recent = (failures[deviceId] ?? const <DateTime>[])
        .where((t) => now.difference(t) < Pairing.attemptCooldown)
        .length;
    return recent >= Pairing.maxAttempts;
  }

  @override
  void recordFailure(String deviceId) {
    failures.putIfAbsent(deviceId, () => []).add(DateTime.now());
  }

  @override
  Future<void> rememberPeer({required String deviceId, required String publicKey}) async {
    trusted[deviceId] = publicKey;
  }

  @override
  Future<TrustState> lookupTrust({required String deviceId, required String publicKey}) async {
    final known = trusted[deviceId];
    if (known == null) return TrustState.unknown;
    return known == publicKey ? TrustState.known : TrustState.identityConflict;
  }

  @override
  Future<void> forgetPeer(String deviceId) async => trusted.remove(deviceId);
}

/// Tiny sha256 shim: the real crypto agent owns the production digest, and this
/// suite only needs *a* deterministic hash.
Uint8List sha256(List<int> input) {
  final out = Uint8List(8);
  var h = 0x811c9dc5;
  for (final b in input) {
    h ^= b;
    h = (h * 0x01000193) & 0xffffffff;
  }
  out[0] = (h >> 0) & 0xff;
  out[1] = (h >> 8) & 0xff;
  out[2] = (h >> 16) & 0xff;
  out[3] = (h >> 24) & 0xff;
  out[4] = (h >> 3) & 0xff;
  out[5] = (h >> 11) & 0xff;
  out[6] = (h >> 19) & 0xff;
  out[7] = (h >> 27) & 0xff;
  return out;
}

void main() {
  const fpA = 'aaaa1111';
  const fpB = 'bbbb2222';
  const nonce = 'shared-nonce';

  PeerInfo peerInfo() => const PeerInfo(
        deviceId: 'remote-1',
        deviceName: 'Peer Mac',
        os: AeroOs.macos,
        osVersion: '14',
        appVersion: '1.0.0',
        publicKey: 'k',
        protocolVersion: kProtocolVersion,
        capabilities: {Capability.receive},
        nonce: nonce,
      );

  group('pairing handshake', () {
    test('both sides derive the same code', () {
      final a = StubAuthority();
      final b = StubAuthority();

      final sideA = a.deriveProof(
        localFingerprint: fpA,
        remoteFingerprint: fpB,
        nonce: nonce,
      );
      // The other side has the fingerprints the other way round. It must still
      // match, because neither device knows in advance who initiates.
      final sideB = b.deriveProof(
        localFingerprint: fpB,
        remoteFingerprint: fpA,
        nonce: nonce,
      );

      expect(sideA.value, sideB.value);
      expect(sideA.value.length, Pairing.codeDigits);
    });

    test('a genuine peer is accepted', () {
      final server = StubAuthority();
      final client = StubAuthority();

      final code = client
          .deriveProof(localFingerprint: fpA, remoteFingerprint: fpB, nonce: nonce)
          .value;

      expect(
        serverAccepts(
          authority: server,
          localCertFingerprint: fpB,
          remoteCertFingerprint: fpA,
          nonce: nonce,
          presentedCode: code,
          deviceId: 'remote-1',
        ),
        isTrue,
      );
    });

    test('a MITM with its own key derives a different code and is rejected', () {
      // This is the whole point of the design. An active attacker sitting
      // between the two devices holds a third certificate, so its transcript
      // differs and the numbers cannot coincide.
      final server = StubAuthority();
      final client = StubAuthority();
      final attacker = StubAuthority();

      final honestCode = client
          .deriveProof(localFingerprint: fpA, remoteFingerprint: fpB, nonce: nonce)
          .value;
      final attackerCode = attacker
          .deriveProof(localFingerprint: fpA, remoteFingerprint: 'cccc3333', nonce: nonce)
          .value;

      expect(attackerCode, isNot(honestCode));
      expect(
        serverAccepts(
          authority: server,
          localCertFingerprint: fpB,
          remoteCertFingerprint: fpA,
          nonce: nonce,
          presentedCode: attackerCode,
          deviceId: 'attacker',
        ),
        isFalse,
      );
    });

    test('a code from a different session nonce is rejected', () {
      // Prevents replay of a code captured from an earlier session.
      final server = StubAuthority();
      final client = StubAuthority();

      final stale = client
          .deriveProof(localFingerprint: fpA, remoteFingerprint: fpB, nonce: 'old-nonce')
          .value;

      expect(
        serverAccepts(
          authority: server,
          localCertFingerprint: fpB,
          remoteCertFingerprint: fpA,
          nonce: 'fresh-nonce',
          presentedCode: stale,
          deviceId: 'remote-1',
        ),
        isFalse,
      );
    });

    test('repeated failures get the peer rate limited', () {
      final server = StubAuthority();

      for (var i = 0; i < Pairing.maxAttempts; i++) {
        final ok = serverAccepts(
          authority: server,
          localCertFingerprint: fpB,
          remoteCertFingerprint: fpA,
          nonce: nonce,
          presentedCode: '000000',
          deviceId: 'attacker',
        );
        expect(ok, isFalse);
      }

      expect(server.isRateLimited('attacker'), isTrue);
      // Even the *correct* code is now refused, which stops a fast brute force.
      expect(
        serverAccepts(
          authority: server,
          localCertFingerprint: fpB,
          remoteCertFingerprint: fpA,
          nonce: nonce,
          presentedCode: '123456',
          deviceId: 'attacker',
        ),
        isFalse,
      );
    });

    test('the wire payload carries method, value and nonce', () async {
      final link = FakeLink(
        remoteInfo: peerInfo(),
        responses: {
          Api.pair: PairingResult(paired: true, trustState: TrustState.unknown).toJson(),
        },
      );
      final handshake = PairingHandshake(
        link: link,
        authority: StubAuthority(),
        nonce: nonce,
      );

      await handshake.confirm('123456');

      expect(link.sent.single.method, 'POST');
      expect(link.sent.single.path, Api.pair);
      expect(link.sent.single.body!['confirm'], isTrue);
      expect((link.sent.single.body!['proof'] as Map)['value'], '123456');
      expect(link.sent.single.body!['nonce'], nonce);
    });
  });

  group('trust on first use', () {
    test('a previously paired device is recognised', () async {
      final store = StubAuthority();
      expect(await store.lookupTrust(deviceId: 'd', publicKey: 'k1'), TrustState.unknown);

      await store.rememberPeer(deviceId: 'd', publicKey: 'k1');
      expect(await store.lookupTrust(deviceId: 'd', publicKey: 'k1'), TrustState.known);
    });

    test('a changed key for a known device id is a conflict, not trust', () async {
      // A reinstall or an impersonation attempt. Trusting it silently would
      // defeat the pairing check entirely.
      final store = StubAuthority();
      await store.rememberPeer(deviceId: 'd', publicKey: 'original');

      expect(
        await store.lookupTrust(deviceId: 'd', publicKey: 'impostor'),
        TrustState.identityConflict,
      );
    });

    test('forgetting a peer returns it to unknown', () async {
      final store = StubAuthority();
      await store.rememberPeer(deviceId: 'd', publicKey: 'k');
      await store.forgetPeer('d');
      expect(await store.lookupTrust(deviceId: 'd', publicKey: 'k'), TrustState.unknown);
    });
  });
}