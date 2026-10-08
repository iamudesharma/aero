// ignore_for_file: avoid_print
import 'dart:io';

import 'package:aero/core/constants.dart';
import 'package:aero/core/crypto/ed25519_identity.dart';
import 'package:aero/core/crypto/sas_pairing.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/network/manual_pairing.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/receive_destination.dart';
import 'package:aero/core/transfer/sender_session.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:flutter_test/flutter_test.dart';

/// Real-socket probe for the manual-pairing tier.
///
/// The manual path is the one tier that bypasses discovery entirely: it turns a
/// pasted string into a [PeerAddress] and dials it. That means it can be verified
/// end-to-end without a second physical device - this stands in for the other
/// device, dialling the running app exactly as a user's pasted string would.
///
/// Run with the Mac app (or Android app) already listening:
///   TGT=192.168.1.25 flutter test tool/manual_connect_probe_test.dart
void main() {
  test('a peer dialled from a manual string pairs and transfers', () async {
    final tmp = await Directory.systemTemp.createTemp('manual_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final host = Platform.environment['TGT'] ?? '192.168.1.25';
    const port = kPreferredPort;

    // 1) Build the payload exactly as the hosting device's UI would.
    final payload = buildManualConnection(
      host: host,
      port: port,
      deviceName: 'Peer',
      deviceId: 'peer-id',
      publicKeyHash: '',
      os: 'macos',
    );
    expect(payload, isNotNull);
    final uri = payload!.toUriString();
    print('PAYLOAD=$uri');

    // 2) Parse it back exactly as the connecting device's UI would.
    final parsed = parseManualConnection(uri);
    expect(parsed.isSuccess, isTrue, reason: parsed.message);
    final connection = parsed.connection!;
    print('PARSED=${connection.host}:${connection.port}');
    expect(connection.address, PeerAddress(host: host, port: port));

    // 3) Dial it over real TLS, with an independent identity.
    final identity = await Ed25519Identity.load(directory: tmp);
    final transport = TcpTlsTransport(identity: identity, port: 0);
    addTearDown(transport.close);
    final store = LocalFileStore(
      baseDirectory: tmp,
      destination: DownloadsDestination(root: Directory('${tmp.path}/dl')),
    );

    final link = await transport.connect(connection.address);
    addTearDown(link.close);
    final info = link.remote!;
    print('CONNECTED to ${info.deviceName} (${info.os.name}) '
        'remoteFp=${link.remoteCertFingerprint?.substring(0, 8)}');
    expect(link.remoteCertFingerprint, isNotNull);

    // 4) Derive the SAS and pair - the same code a user would compare.
    final proof = SasPairingAuthority().deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint!,
      nonce: info.nonce,
    );
    print('SAS=${proof.display}');

    final paired = await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': proof.value},
      'nonce': info.nonce,
    });
    print('PAIR=$paired');
    expect(PairingResult.fromJson(paired).paired, isTrue);

    // 5) Transfer a file over the manually-established link.
    final bytes = List<int>.generate(256 * 1024, (i) => (i * 7) & 0xff);
    final src = File('${tmp.path}/manual.bin')..writeAsBytesSync(bytes);
    final result = await SenderSession(link: link, reader: store, store: store).send([
      LocalFile(id: 'm', path: src.path, name: 'manual.bin', size: bytes.length),
    ]);
    print('TRANSFER ok=${result.ok} failures=${result.failures}');
    expect(result.ok, isTrue, reason: '${result.failures}');
    print('DONE');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
