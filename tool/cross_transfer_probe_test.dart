// ignore_for_file: avoid_print
import 'dart:io';

import 'package:aero/core/constants.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:aero/core/crypto/trust_store.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/sender_session.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:flutter_test/flutter_test.dart';

/// Cross-device real transfer: run from the Mac against the running Android
/// app (which accepts all offers because it was started with
/// --dart-define=AERO_AUTOACCEPT=1), send a file, and publish the resulting
/// payload's hash for adb-side verification.
void main() {
  test('macOS sends a real file to Android over LAN', () async {
    final tmp = await Directory.systemTemp.createTemp('xp_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final identity = await Ed25519Identity.load(directory: tmp);
    final transport = TcpTlsTransport(identity: identity, port: 0);
    addTearDown(transport.close);
    final store = LocalFileStore(baseDirectory: tmp);

    final target = Platform.environment['TGT'] ?? '192.168.1.8';
    final link = await transport.connect(PeerAddress(host: target, port: 44353));
    addTearDown(link.close);
    final info = link.remote!;

    final proof = TrustStore().deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint!,
      nonce: info.nonce,
    );
    await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': proof.value},
      'nonce': info.nonce,
    });

    // 2 MiB of deterministic content.
    final payload = List<int>.generate(2 * 1024 * 1024, (i) => (i * 31) & 0xff);
    final src = File('${tmp.path}/probe.bin')..writeAsBytesSync(payload);

    final session = SenderSession(link: link, reader: store, store: store);
    final sub = session.progress.listen((_) {});
    addTearDown(() => sub.cancel());

    final result = await session.send([
      LocalFile(id: 'p1', path: src.path, name: 'probe.bin', size: payload.length),
    ]);
    print('Transfer completed=${result.completed.length} ok=${result.ok} '
        'rejected=${result.rejected.length} failures=${result.failures}');
    expect(result.ok, isTrue, reason: 'failures: ${result.failures}');
    expect(result.completed.length, 1);

    print('MAC-HW OutPath=${tmp.path}');
    print('PAYLOAD-BYTES=${payload.length}');
  });
}
