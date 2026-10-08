/// Integration tests for [TcpTlsTransport].
///
/// Two transports in one process over 127.0.0.1: one serving a stub [PeerApi],
/// one dialling it. Self-signed certificates are the point, not a shortcut -
/// there is no CA in Aero and these tests must keep working without one.
///
/// ### Why the certificates are ECDSA P-256 and not Ed25519
///
/// `Crypto.curve == 'ed25519'` is about the *device identity* key, not the TLS
/// certificate, and the two must not be conflated. Measured on this SDK
/// (macOS, Dart 3.13): dart:io's BoringSSL build **cannot use an Ed25519
/// certificate in TLS at all** - `SSL_CTX_use_certificateChainBytes` accepts it
/// and the bind succeeds, then every handshake dies with "Connection terminated
/// during handshake", because Ed25519 is not in the signature-algorithm set
/// dart:io offers. The same certificates work perfectly as ECDSA P-256 or RSA
/// certificates. So the ephemeral session certificate generator must emit
/// P-256. See the report attached to `lib/core/transport/tcp_tls_transport.dart`.
///
/// ### Where the certs come from
///
/// [setUpAll] mints fresh ones with `openssl` so the two peers really do have
/// different identities (the fingerprint assertions depend on it). If openssl is
/// missing or refuses, the tests fall back to the long-lived pair pasted below
/// rather than skipping: transport behaviour, not certificate freshness, is what
/// is under test.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:aero/core/constants.dart';
import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transport/tcp_tls_transport.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

// ---------------------------------------------------------------------------
// Certificate material
// ---------------------------------------------------------------------------

/// Fallback for the serving side. Valid until 2036; regenerate if it expires.
const String _alphaCertPem = '''
-----BEGIN CERTIFICATE-----
MIIBajCCARCgAwIBAgIJAJWvpIov0PgXMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMM
D2Flcm8tdGVzdC1hbHBoYTAeFw0yNjEwMDMxNjI2NTNaFw0zNjA5MzAxNjI2NTNa
MBoxGDAWBgNVBAMMD2Flcm8tdGVzdC1hbHBoYTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABKysWkwMD85jS7Rq1P6P0HbswvtJp9QudCOFHLtqpE+3Pbmpyf4xaBbT
lDmQ2dZFgKFJ4IUEMt9OBi7w5D3QG1yjPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0P
AQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjO
PQQDAgNIADBFAiEAnbgwJ8oPjDCnaufKuJBiyChHqFaD/FqK15bPz91Z+AUCIErm
T41H9CP/Kqg9Gx5paIgXqTXLb4EzOk1j6HCqNBbE
-----END CERTIFICATE-----
''';

const String _alphaKeyPem = '''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJoxvcHNyPzE8t8xpYCwuxZNOvGavRlcoQkvZN4QI4eEoAoGCCqGSM49
AwEHoUQDQgAErKxaTAwPzmNLtGrU/o/QduzC+0mn1C50I4Ucu2qkT7c9uanJ/jFo
FtOUOZDZ1kWAoUnghQQy304GLvDkPdAbXA==
-----END EC PRIVATE KEY-----
''';

/// Fallback for the dialling side, so the two ends are distinguishable.
const String _betaCertPem = '''
-----BEGIN CERTIFICATE-----
MIIBZzCCAQ6gAwIBAgIJAIHhsy91seZLMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMM
DmFlcm8tdGVzdC1iZXRhMB4XDTI2MTAwMzE2MjY1M1oXDTM2MDkzMDE2MjY1M1ow
GTEXMBUGA1UEAwwOYWVyby10ZXN0LWJldGEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAT+krHWd+SDi+APD5gGzI0mHTYimlayTjtdznFS4C83zhxeeOOfaVSmylXE
Uia/VF3GRF67w3iRWI6c1Y0pSyyToz8wPTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB
/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0E
AwIDRwAwRAIgAemDo8S53eoP+9uCiz6g1HTc3YE/9A6kvODDJ3lqssACICWLi0ml
98xjDXFx2RH1gFHBMTwmHfJ83GtBQK2f8VtQ
-----END CERTIFICATE-----
''';

const String _betaKeyPem = '''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPMk1GMT0B98Zo9xsD88BvToZGyBDyZexqShiI0En+bqoAoGCCqGSM49
AwEHoUQDQgAE/pKx1nfkg4vgDw+YBsyNJh02IppWsk47Xc5xUuAvN84cXnjjn2lU
pspVxFImv1RdxkReu8N4kViOnNWNKUsskw==
-----END EC PRIVATE KEY-----
''';

late SessionCredentials _serverCreds;
late SessionCredentials _clientCreds;

Future<SessionCredentials> _credentials(
  String commonName,
  String fallbackCert,
  String fallbackKey,
) async {
  final generated = await _generateWithOpenSsl(commonName);
  final cert = generated?.$1 ?? fallbackCert.trim();
  final key = generated?.$2 ?? fallbackKey.trim();
  return SessionCredentials(
    certificatePem: cert,
    privateKeyPem: key,
    fingerprintHex: await _sha256Hex(_derFromPem(cert)),
    publicKeyB64: '',
  );
}

/// Returns `(certPem, keyPem)`, or null if openssl is unusable here.
Future<(String, String)?> _generateWithOpenSsl(String commonName) async {
  Directory? dir;
  try {
    dir = Directory.systemTemp.createTempSync('aero-tls-test-');
    final key = '${dir.path}/key.pem';
    final cert = '${dir.path}/cert.pem';
    // Two commands rather than `req -newkey`: LibreSSL (what ships on macOS)
    // and OpenSSL 3 disagree about `-newkey ec` plus curve selection, while
    // `ecparam` then `req -new -key` works on both.
    final genKey = await Process.run(
      'openssl',
      ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', key],
    );
    if (genKey.exitCode != 0) return null;
    final sign = await Process.run('openssl', [
      'req',
      '-x509',
      '-new',
      '-key',
      key,
      '-out',
      cert,
      '-days',
      '2',
      '-subj',
      '/CN=$commonName',
      '-addext',
      'basicConstraints=critical,CA:FALSE',
      '-addext',
      'keyUsage=critical,digitalSignature',
      '-addext',
      'extendedKeyUsage=serverAuth,clientAuth',
    ]);
    if (sign.exitCode != 0) return null;
    return (File(cert).readAsStringSync(), File(key).readAsStringSync());
  } on ProcessException {
    return null;
  } finally {
    try {
      dir?.deleteSync(recursive: true);
    } on FileSystemException {
      // A leftover temp directory must never fail a test run.
    }
  }
}

/// DER bytes of the first certificate in a PEM blob.
Uint8List _derFromPem(String pem) {
  final body = pem
      .split('\n')
      .where((String line) => !line.startsWith('-----'))
      .join();
  return base64Decode(body);
}

Future<String> _sha256Hex(List<int> bytes) async =>
    (await Sha256().hash(bytes)).bytes
        .map((int b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

bool _isSha256Hex(String? value) =>
    value != null &&
    value.length == 64 &&
    RegExp(r'^[0-9a-f]{64}$').hasMatch(value);

// ---------------------------------------------------------------------------
// Test identity
// ---------------------------------------------------------------------------

/// The smallest honest [DeviceIdentity] the transport needs.
///
/// Only [beginSession] matters here: the transport asks it for a fresh
/// certificate per `serve()`/`connect()`. Returns the same material every call
/// (as a real implementation would for a *reused* key but not a reused
/// certificate), which is fine because the transport never persists it and the
/// tests deliberately compare two peers' fingerprints rather than two sessions'.
class _StubIdentity implements DeviceIdentity {
  const _StubIdentity(this._credentials);

  final SessionCredentials _credentials;

  @override
  String get deviceId => 'stub-device';

  @override
  String get publicKey => _credentials.publicKeyB64;

  @override
  String freshNonce() => 'test-nonce';

  @override
  Future<String> sign(String payload) async => '';

  @override
  Future<bool> verify(String payload, String signatureB64) async => false;

  @override
  Future<SessionCredentials> beginSession() async => _credentials;
}

// ---------------------------------------------------------------------------
// Stub PeerApi
// ---------------------------------------------------------------------------

class _HashResult {
  const _HashResult(this.bytes, this.sha256);

  final int bytes;
  final String sha256;
}

/// A [PeerApi] that exercises the paths the transport owns.
class _StubApi implements PeerApi {
  _StubApi(this.info);

  final PeerInfo info;

  /// Links seen, so tests can inspect what the server side learned.
  final List<PeerLink> links = <PeerLink>[];

  /// Links handed to [onDisconnect].
  final List<PeerLink> disconnected = <PeerLink>[];

  /// A deliberately wrong fingerprint in the info document: the transport must
  /// ignore anything the peer claims about its own certificate.
  static final String decoyFingerprint = List<String>.filled(64, 'f').join();

  @override
  bool isPaired(PeerLink link) => link.isPaired;

  @override
  void onDisconnect(PeerLink link) => disconnected.add(link);

  @override
  Future<ApiResponse> handle(PeerLink link, ApiRequest request) async {
    links.add(link);
    switch (request.path) {
      case Api.info:
        return ApiResponse.json({
          ...info.toJson(),
          'certFingerprint': decoyFingerprint,
        });

      // Echoes one request header so concurrent requests can be told apart.
      case '/v1/echo':
        return ApiResponse.json({
          'echo': request.header('x-echo') ?? '',
          'peerCert': link.remoteCertFingerprint,
          'peerCertVerified':
              link is TcpPeerLink && link.remoteCertFingerprintIsVerified,
        });

      // A handler that speaks the protocol error vocabulary.
      case '/v1/no-space':
        throw PeerException(ApiError.noSpace, 'not enough free space');

      case '/v1/boom':
        throw StateError('handler exploded');

      // Streams the request body through an incremental hash: if the transport
      // buffers instead of streaming, this still works but memory does not, and
      // the byte count is what proves the body arrived intact.
      case '/v1/hash':
        return ApiResponse.json((await _hashBody(request)).toJson());

      // Slow enough to overlap with the other concurrent requests.
      case '/v1/slow':
        await Future<void>.delayed(const Duration(milliseconds: 120));
        return ApiResponse.json({'echo': request.header('x-echo') ?? ''});

      default:
        throw PeerException(ApiError.badRequest, 'no route ${request.path}');
    }
  }

  Future<_HashResult> _hashBody(ApiRequest request) async {
    // Incremental hashing, exactly like the real receiver: proves the body can
    // be consumed chunk by chunk instead of being collected.
    final sink = Sha256().newHashSink();
    var bytes = 0;
    await for (final chunk in request.body) {
      bytes += chunk.length;
      sink.add(chunk);
    }
    sink.close();
    final digest = await sink.hash();
    return _HashResult(
      bytes,
      digest.bytes.map((int b) => b.toRadixString(16).padLeft(2, '0')).join(),
    );
  }
}

extension on _HashResult {
  Map<String, dynamic> toJson() => {'bytes': bytes, 'sha256': sha256};
}

/// Pseudorandom bytes, deterministic per seed so a failure is reproducible.
Stream<List<int>> _pseudoRandomBytes(int totalBytes, int chunkSize, int seed) {
  final random = Random(seed);
  var produced = 0;
  return Stream<List<int>>.periodic(const Duration(milliseconds: 1), (_) {
    final take = min(chunkSize, totalBytes - produced);
    produced += take;
    final chunk = Uint8List(take);
    for (var i = 0; i < take; i++) {
      chunk[i] = random.nextInt(256);
    }
    return chunk;
  }).take((totalBytes / chunkSize).ceil());
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PeerInfo _serverInfo = PeerInfo(
  deviceId: 'server-device',
  deviceName: 'Test Server',
  os: AeroOs.macos,
  osVersion: '15.0',
  appVersion: '1.0.0',
  publicKey: 'c2VydmVyLWtleQ==',
  protocolVersion: kProtocolVersion,
  capabilities: {Capability.send, Capability.receive, Capability.multiFile},
  nonce: 'server-nonce',
);

const PeerInfo _clientInfo = PeerInfo(
  deviceId: 'client-device',
  deviceName: 'Test Client',
  os: AeroOs.android,
  osVersion: '17',
  appVersion: '1.0.0',
  publicKey: 'Y2xpZW50LWtleQ==',
  protocolVersion: kProtocolVersion,
  capabilities: {Capability.send, Capability.receive},
  nonce: 'client-nonce',
  port: 1234,
);

void main() {
  setUpAll(() async {
    _serverCreds = await _credentials(
      'aero-test-server',
      _alphaCertPem,
      _alphaKeyPem,
    );
    _clientCreds = await _credentials(
      'aero-test-client',
      _betaCertPem,
      _betaKeyPem,
    );
  });

  group('lifecycle', () {
    late TcpTlsTransport server;
    late _StubApi api;

    setUp(() async {
      api = _StubApi(_serverInfo);
      server = TcpTlsTransport(
        identity: _StubIdentity(_serverCreds),
        port: 0,
      );
      await server.serve(api);
    });

    tearDown(() async {
      await server.close();
    });

    test('serve() binds and exposes a truthful boundPort', () async {
      expect(server.name, 'tcp-tls');
      final port = server.boundPort;
      expect(port, isNotNull);
      expect(port, greaterThan(0));
      expect(port, isNot(kPreferredPort), reason: 'port 0 means ephemeral');

      // The advertised port must be the one a peer can actually reach: dial it.
      final dialler = TcpTlsTransport(identity: _StubIdentity(_clientCreds));
      addTearDown(dialler.close);
      await expectLater(
        dialler.connect(PeerAddress(host: '127.0.0.1', port: port!)),
        completes,
      );
    });

    test('certFingerprints reports the current session, not a cached one', () {
      expect(server.certFingerprints, hasLength(1));
      expect(_isSha256Hex(server.certFingerprints.single), isTrue);
      expect(server.certFingerprints.single, _serverCreds.fingerprintHex);
    });

    test('close() is idempotent and clears boundPort', () async {
      await server.close();
      await server.close();
      await server.close();
      expect(server.boundPort, isNull);
    });

    test('connect() after close() fails as a PeerException', () async {
      await server.close();
      final transport = TcpTlsTransport(
        identity: _StubIdentity(_clientCreds),
      );
      await expectLater(
        transport.connect(
          const PeerAddress(host: '127.0.0.1', port: kPreferredPort),
        ),
        throwsA(
          isA<PeerException>().having(
            (PeerException e) => e.code,
            'code',
            ApiError.internal,
          ),
        ),
      );
      await transport.close();
    });

    test('serve() twice is refused rather than silently re-binding', () {
      expect(
        () => server.serve(api),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('preferred port fallback', () {
    test('advertises an ephemeral port when kPreferredPort is unavailable',
        () async {
      // Try to occupy the preferred port ourselves. Another process may already
      // hold it - which exercises the same code path - so a failure here is not
      // a reason to skip.
      ServerSocket? squatter;
      try {
        squatter = await ServerSocket.bind(
          InternetAddress.anyIPv4,
          kPreferredPort,
        );
      } on SocketException {
        // Someone else owns it; the fallback must engage all the same.
      }
      addTearDown(() => squatter?.close());

      final transport = TcpTlsTransport(
        identity: _StubIdentity(_serverCreds),
      );
      addTearDown(transport.close);
      await transport.serve(_StubApi(_serverInfo));

      expect(transport.boundPort, isNotNull);
      if (squatter != null) {
        expect(
          transport.boundPort,
          isNot(kPreferredPort),
          reason: 'must not advertise a port it does not hold',
        );
      }

      // Whatever it advertises, it must actually work.
      final link = await transport.connect(
        PeerAddress(host: '127.0.0.1', port: transport.boundPort!),
      );
      addTearDown(link.close);
      expect((await link.getJson(Api.info))['deviceId'], _serverInfo.deviceId);
    });
  });

  group('connect + handshake', () {
    late TcpTlsTransport server;
    late TcpTlsTransport client;
    late _StubApi api;

    setUp(() async {
      api = _StubApi(_serverInfo);
      // port 0 keeps these tests independent of whoever else on the machine is
      // holding kPreferredPort (parallel test runs, a real instance of the app).
      server = TcpTlsTransport(identity: _StubIdentity(_serverCreds), port: 0);
      client = TcpTlsTransport(identity: _StubIdentity(_clientCreds));
      await server.serve(api);
    });

    tearDown(() async {
      await client.close();
      await server.close();
    });

    Future<TcpPeerLink> connect() async =>
        await client.connect(
          PeerAddress(host: '127.0.0.1', port: server.boundPort!),
        ) as TcpPeerLink;

    test('GET /v1/info populates remote', () async {
      final link = await connect();
      expect(link.transportName, 'tcp-tls');
      final remote = link.remote;
      expect(remote, isNotNull);
      expect(remote!.deviceId, _serverInfo.deviceId);
      expect(remote.deviceName, _serverInfo.deviceName);
      expect(remote.os, AeroOs.macos);
      expect(remote.protocolVersion, kProtocolVersion);
      expect(remote.isCompatible, isTrue);
      expect(remote.canReceive, isTrue);
      expect(remote.nonce, _serverInfo.nonce);
    });

    test('remoteCertFingerprint is the real certificate, not a claim', () async {
      final link = await connect();

      // The server's own document contains a decoy fingerprint; the transport
      // must not believe it.
      final info = await link.getJson(Api.info);
      expect(info['certFingerprint'], _StubApi.decoyFingerprint);

      expect(link.remoteCertFingerprint, _serverCreds.fingerprintHex);
      expect(link.remoteCertFingerprintIsVerified, isTrue);
      expect(link.localCertFingerprint, _clientCreds.fingerprintHex);
      expect(
        link.remoteCertFingerprint,
        isNot(_clientCreds.fingerprintHex),
        reason: 'the two ends must be distinguishable',
      );
    });

    test('the serving side learns the peer fingerprint but cannot verify it',
        () async {
      // Documented dart:io limitation: a server cannot validate a self-signed
      // client certificate without aborting the handshake, so it falls back to
      // the fingerprint the client asserted - and says so.
      final link = await connect();
      final echo = await link.getJson('/v1/echo');
      expect(echo['peerCert'], _clientCreds.fingerprintHex);
      expect(echo['peerCertVerified'], isFalse);

      expect(api.links, hasLength(greaterThanOrEqualTo(1)));
      expect(api.links.last, isA<TcpPeerLink>());
      final serverSide = api.links.whereType<TcpPeerLink>().last;
      expect(serverSide.remoteCertFingerprint, _clientCreds.fingerprintHex);
      expect(serverSide.remoteCertFingerprintIsVerified, isFalse);
      expect(serverSide.isInbound, isTrue);
    });

    test('isPaired starts false and is settable by the pairing layer', () async {
      final link = await connect();
      expect(link.isPaired, isFalse);
      // The pairing layer flips this once the six digits match. Note the server
      // side has its own link object with its own flag: pairing state is not
      // shared in-band, which is why the SAS has to be compared by a human.
      expect(api.links.whereType<TcpPeerLink>().last.isPaired, isFalse);
      link.isPaired = true;
      expect(link.isPaired, isTrue);
      expect(api.isPaired(link), isTrue);
    });

    test('requestJson round-trips a body and headers', () async {
      final link = await connect();
      final reply = await link.requestJson(
        'POST',
        '/v1/echo',
        body: {'ignored': true},
        headers: {'x-echo': 'hello'},
      );
      expect(reply['echo'], 'hello');
    });

    test('an unknown route surfaces as PeerException(badRequest)', () async {
      final link = await connect();
      await expectLater(
        link.getJson('/v1/nope'),
        throwsA(
          isA<PeerException>()
              .having((PeerException e) => e.code, 'code', ApiError.badRequest)
              .having((PeerException e) => e.message, 'message',
                  contains('no route')),
        ),
      );
    });

    test('a handler PeerException round-trips code, message and status',
        () async {
      final link = await connect();
      await expectLater(
        link.getJson('/v1/no-space'),
        throwsA(
          isA<PeerException>()
              .having((PeerException e) => e.code, 'code', ApiError.noSpace)
              .having((PeerException e) => e.httpStatus, 'httpStatus', 507)
              .having((PeerException e) => e.message, 'message',
                  'not enough free space'),
        ),
      );
    });

    test('an unexpected handler error becomes 500/internal, not a hang',
        () async {
      final link = await connect();
      await expectLater(
        link.getJson('/v1/boom'),
        throwsA(
          isA<PeerException>().having(
            (PeerException e) => e.code,
            'code',
            ApiError.internal,
          ),
        ),
      );
    });

    test('a pinned peer certificate makes the serving side verifiable too',
        () async {
      // The counterpart to the limitation above: when the listener has something
      // to verify a client certificate against, TLS does hand it over and the
      // fingerprint stops being a claim. This is the trust-on-first-use hook the
      // pairing layer needs, proven rather than asserted.
      final pinning = TcpTlsTransport(
        identity: _StubIdentity(_serverCreds),
        port: 0,
        trustedPeerCertificatePems: [_clientCreds.certificatePem],
      );
      final pinningApi = _StubApi(_serverInfo);
      addTearDown(pinning.close);
      await pinning.serve(pinningApi);

      final link = await client.connect(
        PeerAddress(host: '127.0.0.1', port: pinning.boundPort!),
      );
      addTearDown(link.close);
      expect((await link.getJson(Api.info))['deviceId'], _serverInfo.deviceId);

      final serverSide = pinningApi.links.whereType<TcpPeerLink>().last;
      expect(serverSide.remoteCertFingerprint, _clientCreds.fingerprintHex);
      expect(
        serverSide.remoteCertFingerprintIsVerified,
        isTrue,
        reason: 'the fingerprint came out of the TLS handshake',
      );
    });

    test('a non-persistent connection reports the peer disconnecting',
        () async {
      final link = await client.connect(
        PeerAddress(host: '127.0.0.1', port: server.boundPort!),
      );
      // `Connection: close` rides through requestJson's header passthrough, so
      // the server sees a connection that will not be reused - which is the only
      // disconnect signal dart:io exposes for HTTP.
      await link.requestJson(
        'GET',
        Api.info,
        headers: {'connection': 'close'},
      );
      // Delivered after the response is written, so give the server a turn.
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(api.disconnected, isNotEmpty);
      expect(api.disconnected.last.remoteCertFingerprint, isNotNull);
    });

    test('link.close() is idempotent', () async {
      final link = await connect();
      await link.getJson(Api.info);
      await link.close();
      await link.close();
      // The server notices the peer went away at some point; assert we simply do
      // not hang and that the link stopped working.
      await expectLater(link.getJson(Api.info), throwsA(anything));
    });
  });

  group('streaming uploads', () {
    late TcpTlsTransport server;
    late TcpTlsTransport client;
    late _StubApi api;
    late TcpPeerLink link;

    setUp(() async {
      api = _StubApi(_serverInfo);
      // port 0 keeps these tests independent of whoever else on the machine is
      // holding kPreferredPort (parallel test runs, a real instance of the app).
      server = TcpTlsTransport(identity: _StubIdentity(_serverCreds), port: 0);
      client = TcpTlsTransport(identity: _StubIdentity(_clientCreds));
      await server.serve(api);
      link = await client.connect(
        PeerAddress(host: '127.0.0.1', port: server.boundPort!),
      ) as TcpPeerLink;
    });

    tearDown(() async {
      await client.close();
      await server.close();
    });

    test('putStream delivers a byte-identical multi-chunk body', () async {
      // 5 MiB in 512 KiB chunks: more than one chunk, so a transport that
      // collapsed the stream, dropped a chunk, or trusted Content-Length would
      // fail here rather than on the happy path.
      const totalBytes = 5 * 1024 * 1024;
      const chunkSize = 512 * 1024;
      final body = <int>[
        for (final chunk
            in await _pseudoRandomBytes(totalBytes, chunkSize, 42).toList())
          ...chunk,
      ];
      final expected = await _sha256Hex(body);

      final progress = <int>[];
      final reply = await link.putStream(
        '/v1/hash',
        _pseudoRandomBytes(totalBytes, chunkSize, 42),
        contentLength: totalBytes,
        headers: {Header.sha256: expected},
        onProgress: progress.add,
      );

      expect(reply['bytes'], totalBytes);
      expect(reply['sha256'], expected);
      expect(progress, isNotEmpty);
      expect(progress.last, totalBytes);
      // Monotonic and only ever the values actually streamed.
      for (var i = 1; i < progress.length; i++) {
        expect(progress[i], greaterThan(progress[i - 1]));
        expect(progress[i] - progress[i - 1], chunkSize);
      }
    });

    test('putStream honours an error response', () async {
      await expectLater(
        link.putStream(
          '/v1/no-space',
          _pseudoRandomBytes(64 * 1024, 4096, 7),
          contentLength: 64 * 1024,
        ),
        throwsA(
          isA<PeerException>()
              .having((PeerException e) => e.code, 'code', ApiError.noSpace),
        ),
      );
    });

    test('concurrent requests do not corrupt each other', () async {
      // Interleave a large streaming upload with a burst of small requests that
      // each carry a unique value. dart:io pools sockets underneath, so this is
      // also the regression test for responses being attributed to the wrong
      // request.
      final upload = link.putStream(
        '/v1/hash',
        _pseudoRandomBytes(2 * 1024 * 1024, 256 * 1024, 9),
        contentLength: 2 * 1024 * 1024,
      );

      final echoes = await Future.wait(
        List<Future<Map<String, dynamic>>>.generate(12, (int i) {
          final tag = 'req-$i-${i * 7919}';
          // Half the burst goes to a slow route, so replies interleave with the
          // upload and with each other.
          final path = i.isEven ? '/v1/slow' : '/v1/echo';
          return link
              .requestJson('GET', path, headers: {'x-echo': tag})
              .then((Map<String, dynamic> m) => m..['tag'] = tag);
        }),
      );

      for (var i = 0; i < echoes.length; i++) {
        expect(echoes[i]['echo'], 'req-$i-${i * 7919}');
        expect(echoes[i]['tag'], 'req-$i-${i * 7919}');
      }

      final uploadReply = await upload;
      expect(uploadReply['bytes'], 2 * 1024 * 1024);
    });

    test('two links from one transport both work', () async {
      final second = await client.connect(
        PeerAddress(host: '127.0.0.1', port: server.boundPort!),
      ) as TcpPeerLink;
      addTearDown(second.close);

      final replies = await Future.wait([
        link.getJson(Api.info),
        second.getJson(Api.info),
        link.getJson('/v1/echo'),
      ]);
      expect(replies[0]['deviceId'], _serverInfo.deviceId);
      expect(replies[1]['deviceId'], _serverInfo.deviceId);
      expect(replies[2]['peerCert'], _clientCreds.fingerprintHex);
    });

    test('the handshake is symmetric: the other role decodes the same way',
        () async {
      // The "server" in the previous tests is fixed to one PeerInfo, so run a
      // second pair with the roles' identities swapped. If anything in the
      // handshake were direction-specific (a header only sent one way, a field
      // only parsed on one side) this is where it would show.
      final other =
          TcpTlsTransport(identity: _StubIdentity(_clientCreds), port: 0);
      addTearDown(other.close);
      await other.serve(_StubApi(_clientInfo));

      final reversed = await client.connect(
        PeerAddress(host: '127.0.0.1', port: other.boundPort!),
      ) as TcpPeerLink;
      addTearDown(reversed.close);

      expect(reversed.remote!.deviceId, _clientInfo.deviceId);
      expect(reversed.remote!.os, AeroOs.android);
      expect(reversed.remote!.port, _clientInfo.port);
      expect(reversed.remote!.capabilities, _clientInfo.capabilities);
      expect(reversed.remoteCertFingerprint, _clientCreds.fingerprintHex);
    });
  });

  group('connect failures', () {
    test('a refused connection becomes PeerException(internal)', () async {
      // Bind then immediately release, so the port is almost certainly unused.
      final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final deadPort = probe.port;
      await probe.close();

      final transport = TcpTlsTransport(
        identity: _StubIdentity(_clientCreds),
      );
      addTearDown(transport.close);

      await expectLater(
        transport.connect(
          PeerAddress(host: '127.0.0.1', port: deadPort),
        ),
        throwsA(
          isA<PeerException>().having(
            (PeerException e) => e.code,
            'code',
            ApiError.internal,
          ),
        ),
      );
    });

    test('a peer that never answers /v1/info times out', () async {
      // A TLS listener that completes the handshake and then says nothing: the
      // connect budget must cover the whole exchange, not just the socket.
      final mute =
          TcpTlsTransport(identity: _StubIdentity(_serverCreds), port: 0);
      await mute.serve(_MuteApi());
      addTearDown(mute.close);

      final transport = TcpTlsTransport(
        identity: _StubIdentity(_clientCreds),
        connectTimeout: const Duration(milliseconds: 400),
      );
      addTearDown(transport.close);

      await expectLater(
        transport.connect(
          PeerAddress(host: '127.0.0.1', port: mute.boundPort!),
        ),
        throwsA(
          isA<PeerException>()
              .having((PeerException e) => e.code, 'code', ApiError.internal)
              .having((PeerException e) => e.message, 'message', 'connect timeout'),
        ),
      );
    }, timeout: const Timeout(Duration(seconds: 20)));
  });

  group('socket tuning', () {
    test('TCP_NODELAY and the buffer sizes are really applied', () async {
      // The option *ids* differ per platform and getting them wrong fails
      // silently - `ENOPROTOOPT` for a bad id, and on Darwin `0x10` is
      // TCP_KEEPALIVE, not TCP_NODELAY - so assert against the live socket.
      final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(listener.close);
      final accepted = <Socket>[];
      listener.listen(accepted.add);
      final client = await Socket.connect('127.0.0.1', listener.port);
      addTearDown(client.close);
      await Future<void>.delayed(Duration.zero);
      final server = accepted.single;

      int readInt(Socket socket, int level, int option) => ByteData.view(
            socket
                .getRawOption(RawSocketOption.fromInt(level, option, 0))
                .buffer,
          ).getInt32(0, Endian.host);

      final sndBefore =
          readInt(server, RawSocketOption.levelSocket, 0x1001);
      final rcvBefore =
          readInt(server, RawSocketOption.levelSocket, 0x1002);

      tuneSocket(server, role: 'test');

      // Linux reports the requested size; BSD-derived stacks may round or clamp,
      // and macOS links the two buffers, so only require "not smaller".
      expect(
        readInt(server, RawSocketOption.levelSocket, 0x1001),
        greaterThanOrEqualTo(sndBefore),
      );
      expect(
        readInt(server, RawSocketOption.levelSocket, 0x1002),
        greaterThanOrEqualTo(rcvBefore),
      );
      // macOS reports 4 for an enabled TCP_NODELAY and 1 elsewhere: enabled is
      // simply "non-zero" whichever platform we are on.
      expect(
        readInt(server, RawSocketOption.levelTcp, 1),
        isNot(0),
        reason: 'TCP_NODELAY must be on',
      );
    });

    test('tuning a dead socket is swallowed, never fatal', () async {
      final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final accepted = <Socket>[];
      listener.listen(accepted.add);
      final client = await Socket.connect('127.0.0.1', listener.port);
      await Future<void>.delayed(Duration.zero);
      final server = accepted.single;
      await client.close();
      await server.close();
      // Every option now fails; a transport must not turn that into a crash.
      expect(() => tuneSocket(server, role: 'test'), returnsNormally);
      await listener.close();
    });
  });

  group('writeApiResponse', () {
    late HttpServer plain;
    late SecurityContext context;

    setUp(() async {
      context = SecurityContext(withTrustedRoots: false);
      context.useCertificateChainBytes(
        utf8.encode(_serverCreds.certificatePem),
      );
      context.usePrivateKeyBytes(utf8.encode(_serverCreds.privateKeyPem));
      plain = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        context,
      );
      plain.listen((HttpRequest req) async {
        switch (req.uri.path) {
          case '/json':
            await writeApiResponse(
              req.response,
              ApiResponse.json({'hello': 'world'}, status: 201),
            );
          case '/bytes':
            await writeApiResponse(
              req.response,
              ApiResponse.bytes(<int>[1, 2, 3, 4, 5]),
            );
          case '/empty':
            await writeApiResponse(req.response, ApiResponse.json({}, status: 204));
          default:
            req.response.statusCode = HttpStatus.internalServerError;
            req.response.write('not an envelope');
            await req.response.close();
        }
      });
    });

    tearDown(() async {
      await plain.close(force: true);
    });

    SecurityContext clientContext() {
      final ctx = SecurityContext(withTrustedRoots: false);
      ctx.useCertificateChainBytes(utf8.encode(_clientCreds.certificatePem));
      ctx.usePrivateKeyBytes(utf8.encode(_clientCreds.privateKeyPem));
      return ctx;
    }

    /// A link aimed at [plain], built exactly the way the transport builds one -
    /// no injected client, so the TLS policy under test is the real one.
    TcpPeerLink linkToPlainServer() => TcpPeerLink.client(
          host: '127.0.0.1',
          port: plain.port,
          context: clientContext(),
          localCertFingerprint: _clientCreds.fingerprintHex,
          onClosed: (_) {},
        );

    test('json bodies get application/json and the right status', () async {
      final link = linkToPlainServer();
      addTearDown(link.close);

      final reply = await link.getJson('/json');
      expect(reply, {'hello': 'world'});

      // Read the raw response to check the wire format, not just the decode.
      final raw = HttpClient(context: clientContext())
        ..badCertificateCallback = (X509Certificate _, String _, int _) => true;
      addTearDown(() => raw.close(force: true));
      final request = await raw.getUrl(
        Uri.parse('https://127.0.0.1:${plain.port}/json'),
      );
      final response = await request.close();
      expect(response.statusCode, 201);
      expect(response.headers.contentType?.mimeType, 'application/json');
      expect(await response.transform(utf8.decoder).join(), '{"hello":"world"}');
    });

    test('byte bodies get application/octet-stream', () async {
      final raw = HttpClient(context: clientContext())
        ..badCertificateCallback = (X509Certificate _, String _, int _) => true;
      addTearDown(() => raw.close(force: true));
      final request = await raw.getUrl(
        Uri.parse('https://127.0.0.1:${plain.port}/bytes'),
      );
      final response = await request.close();
      expect(
        response.headers.contentType?.mimeType,
        'application/octet-stream',
      );
      expect(await response.expand((List<int> c) => c).toList(), [1, 2, 3, 4, 5]);
    });

    test('a 2xx with an empty body decodes to an empty map', () async {
      final link = linkToPlainServer();
      addTearDown(link.close);
      expect(await link.getJson('/empty'), isEmpty);
    });

    test('a non-2xx without an envelope degrades to internal', () async {
      final link = linkToPlainServer();
      addTearDown(link.close);

      await expectLater(
        link.getJson('/nope'),
        throwsA(
          isA<PeerException>()
              .having((PeerException e) => e.code, 'code', ApiError.internal)
              .having((PeerException e) => e.message, 'message', contains('500')),
        ),
      );
    });

    test('an inbound link refuses to send instead of guessing an address',
        () async {
      final link = TcpPeerLink(
        client: HttpClient(),
        localCertFingerprint: _clientCreds.fingerprintHex,
        onClosed: (_) {},
      );
      addTearDown(link.close);

      await expectLater(
        link.getJson(Api.info),
        throwsA(
          isA<PeerException>().having(
            (PeerException e) => e.message,
            'message',
            contains('inbound link has no peer address'),
          ),
        ),
      );
    });
  });
}

/// A [PeerApi] that accepts connections and never answers: the connect timeout
/// must still fire.
class _MuteApi implements PeerApi {
  @override
  bool isPaired(PeerLink link) => false;

  @override
  void onDisconnect(PeerLink link) {}

  @override
  Future<ApiResponse> handle(PeerLink link, ApiRequest request) =>
      Completer<ApiResponse>().future;
}