// ignore_for_file: avoid_print
import 'dart:io';

import 'package:aero/core/constants.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:aero/core/crypto/trust_store.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:flutter_test/flutter_test.dart';

/// Cross-device probe: run from the Mac against the running Android app to
/// prove a transport client on one machine can complete a real TLS handshake
/// and SAS pairing against the other machine over the LAN.
void main() {
  test('macOS <-> Android TLS handshake + SAS pairing', () async {
    final tmp = await Directory.systemTemp.createTemp('xp_ident_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final identity = await Ed25519Identity.load(directory: tmp);
    final transport = TcpTlsTransport(identity: identity, port: 0);
    addTearDown(transport.close);

    final target = Platform.environment['TGT'] ?? '192.168.1.8';
    final link = await transport.connect(PeerAddress(host: target, port: 44353));

    final info = link.remote!;
    addTearDown(link.close);
    print('GET /v1/info -> ${info.deviceName} (${info.os.name})');
    expect(info.port, 44353);

    final auth = TrustStore();
    final proof = auth.deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint!,
      nonce: info.nonce,
    );
    print('derived SAS: ${proof.display}');

    final result = await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': proof.value},
      'nonce': info.nonce,
    });
    print('PAIR RESULT: $result');
    expect(result['paired'], isTrue,
        reason: 'cross-device pairing must succeed; got $result');
  });
}
