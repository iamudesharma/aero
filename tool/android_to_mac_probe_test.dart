// ignore_for_file: avoid_print
import 'dart:io';

import 'package:aero/core/constants.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:aero/core/crypto/trust_store.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/sender_session.dart';
import 'package:aero/core/transfer/receive_destination.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:flutter_test/flutter_test.dart';

/// The direction the user reported failing: Android sending to the Mac.
/// Run from the Mac against the *Mac's own* running app is meaningless, so this
/// stands in for the Android sender: a second independent identity connects to
/// the Mac's live server exactly as the phone does, and verifies the pairing
/// code the Mac computes matches what this sender derives.
void main() {
  test('a sender pairs with the live Mac and transfers', () async {
    final tmp = await Directory.systemTemp.createTemp('a2m_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final identity = await Ed25519Identity.load(directory: tmp);
    final transport = TcpTlsTransport(identity: identity, port: 0);
    addTearDown(transport.close);
    final store = LocalFileStore(
      baseDirectory: tmp,
      destination: DownloadsDestination(root: Directory('${tmp.path}/dl')),
    );

    final host = Platform.environment['TGT'] ?? '192.168.1.25';
    final link = await transport.connect(PeerAddress(host: host, port: 44353));
    addTearDown(link.close);

    final info = link.remote!;
    print('connected to ${info.deviceName} (${info.os.name})');

    final proof = TrustStore().deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint!,
      nonce: info.nonce,
    );
    print('sender derived code: ${proof.display}');

    final paired = await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': proof.value},
      'nonce': info.nonce,
    });
    print('pair result: $paired');
    expect(PairingResult.fromJson(paired).paired, isTrue,
        reason: 'the Mac must accept the code this sender displays');

    final payload = List<int>.generate(1024 * 1024, (i) => (i * 17) & 0xff);
    final src = File('${tmp.path}/from-phone.bin')..writeAsBytesSync(payload);

    final result = await SenderSession(link: link, reader: store, store: store).send([
      LocalFile(id: 'p', path: src.path, name: 'from-phone.bin', size: payload.length),
    ]);
    print('transfer ok=${result.ok} failures=${result.failures}');
    expect(result.ok, isTrue, reason: '${result.failures}');
  });
}
