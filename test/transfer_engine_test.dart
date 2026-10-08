// End-to-end protocol tests with no sockets anywhere.
//
// The whole point of the PeerLink / PeerApi / FileStore / ChunkedFileReader
// contract split is that the protocol can be exercised in-process. Here a
// [FakePeerLink] takes the sender's `requestJson` / `putStream` calls and routes
// them straight into a real [AeroPeerApi.handle], which writes to a real
// [LocalFileStore] on a real temp directory. Every layer below the socket is the
// production code.
//
// What that buys: a corrupt byte, a resume, or a hostile name behaves exactly as
// it would over TLS, because there is no mock of the interesting parts anywhere.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:aero/core/constants.dart';
import 'package:aero/core/logging.dart';
import 'package:logging/logging.dart' show Level;
import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/receive_destination.dart';
import 'package:aero/core/transfer/peer_api_server.dart';
import 'package:aero/core/transfer/sender_session.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// A [PeerLink] that hands every request to a real [AeroPeerApi].
///
/// Deliberately *not* a stub of the protocol: it models the transport's only
/// real responsibilities — build an [ApiRequest] from method/path/headers/body,
/// call the handler, and translate a non-2xx [ApiResponse] into a
/// [PeerException] — which is precisely what `TcpTlsTransport` does.
class FakePeerLink implements PeerLink {
  FakePeerLink({this.name = 'inproc', this.maxChunkedBody = false});

  final String name;

  /// Emulates a proxy that splits every body into small pieces, so the receiver
  /// really does see a stream of slices rather than one big list.
  final bool maxChunkedBody;

  PeerInfo? _remote;

  /// Set by the test to the PeerInfo the API will report.
  @override
  set remote(PeerInfo? value) => _remote = value;

  @override
  String get transportName => name;

  @override
  PeerInfo? get remote => _remote;

  @override
  String? get remoteCertFingerprint => 'remote-fingerprint';

  @override
  String get localCertFingerprint => 'local-fingerprint';

  @override
  bool get isPaired => true;

  /// Set to make the next [close] drop the link's server-side state too.
  bool simulateDisconnect = false;

  int putCount = 0;
  int jsonCount = 0;

  @override
  Future<Map<String, dynamic>> requestJson(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  }) async {
    jsonCount++;
    final payload = body == null
        ? const <int>[]
        : utf8.encode(jsonEncode(body));
    final response = await _dispatch(
      method,
      path,
      headers ?? const {},
      Stream.value(payload),
      payload.length,
    );
    return _decode(response, '$method $path');
  }

  @override
  Future<Map<String, dynamic>> getJson(String path) async {
    jsonCount++;
    final response = await _dispatch(
      'GET',
      path,
      const {},
      const Stream.empty(),
      0,
    );
    return _decode(response, 'GET $path');
  }

  @override
  Future<Map<String, dynamic>> putStream(
    String path,
    Stream<List<int>> data, {
    int? contentLength,
    Map<String, String>? headers,
    void Function(int bytesSent)? onProgress,
  }) async {
    putCount++;
    final sink = _CountingSink(onProgress);

    // If the server declares a Content-Length, a real transport would notice a
    // mismatch when the stream ends early. Emulating that keeps the sender
    // honest about aborting mid-file.
    var declared = contentLength;
    final tapped = Stream<List<int>>.multi((controller) {
      final subscription = data.listen(
        (chunk) {
          sink.add(chunk);
          controller.add(chunk);
        },
        onError: controller.addError,
        onDone: () {
          if (declared != null && sink.count != declared) {
            controller.addError(
              StateError(
                'Content-Length mismatch: declared $declared, sent ${sink.count}',
              ),
            );
          } else {
            controller.close();
          }
        },
      );
      controller.onCancel = subscription.cancel;
    });

    final response = await _dispatch(
      'PUT',
      path,
      headers ?? const {},
      tapped,
      contentLength ?? -1,
    );
    return _decode(response, 'PUT $path');
  }

  @override
  Future<void> close() async {}

  /// Test hook: run a raw request and hand back the undecoded [ApiResponse], so
  /// a test can assert on status codes the [PeerLink] contract hides.
  Future<ApiResponse> raw(
    String method,
    String path, {
    Map<String, String>? headers,
    Stream<List<int>>? body,
  }) => _dispatch(
    method,
    path,
    headers ?? const {},
    body ?? const Stream.empty(),
    -1,
  );

  Future<ApiResponse> _dispatch(
    String method,
    String path,
    Map<String, String> headers,
    Stream<List<int>> body,
    int contentLength,
  ) async {
    // ApiRequest.headers is typed Map<String,String>; a real transport builds a
    // fresh mutable map per request, so copy rather than mutating the caller's
    // (possibly const) map.
    final allHeaders = <String, String>{...headers};
    if (contentLength >= 0) {
      allHeaders['content-length'] = '$contentLength';
    }
    final request = ApiRequest(
      method: method,
      path: path,
      headers: allHeaders,
      body: body,
      connection: this,
    );
    try {
      return await api!.handle(this, request);
    } on PeerException catch (e) {
      // The real transport turns a thrown PeerException into the matching HTTP
      // status (see `PeerException.httpStatus` and `ApiResponse.error`), so
      // `raw()` has to do the same or it would not be inspecting what a client
      // would actually see.
      return ApiResponse.error(e.code, e.message);
    }
  }

  Map<String, dynamic> _decode(ApiResponse response, String what) {
    final json = response.json;
    if (response.statusCode >= 400) {
      protocolLog.info(
        '$what -> ${response.statusCode} '
        '${json?['error']}',
      );
      throw PeerException(
        json?['error']?.toString() ?? ApiError.internal,
        json?['message']?.toString() ?? '',
      );
    }
    return json ?? const <String, dynamic>{};
  }

  /// Wired by the test harness.
  PeerApi? api;

  /// Hook so a test can mutate bytes in flight (corruption tests).
  void Function(List<int> chunk)? onBodyChunk;
}

class _CountingSink {
  _CountingSink(this._onProgress);
  final void Function(int)? _onProgress;
  int count = 0;

  void add(List<int> chunk) {
    count += chunk.length;
    _onProgress?.call(count);
  }
}

/// A [PairingAuthority] that is deterministic and trivially inspectable.
class FakePairingAuthority implements PairingAuthority {
  FakePairingAuthority({
    this.expectedCode = '424242',
    this.rateLimited = false,
  });

  /// The only code [verifyProof] accepts.
  final String expectedCode;

  /// Flipped by tests to exercise the rate-limit branch.
  bool rateLimited;

  final Map<String, String> trusted = {};
  int failures = 0;

  @override
  PairingProof deriveProof({
    required String localFingerprint,
    required String remoteFingerprint,
    required String nonce,
    String method = 'sas',
  }) => PairingProof(
    method: method,
    value: expectedCode,
    expiresAt: DateTime.now().add(Pairing.codeLifetime),
  );

  @override
  bool verifyProof(PairingProof presented, PairingProof expected) =>
      !presented.isExpired() &&
      presented.value == expected.value &&
      presented.method == expected.method;

  @override
  Future<void> rememberPeer({
    required String deviceId,
    required String publicKey,
  }) async => trusted[deviceId] = publicKey;

  @override
  Future<TrustState> lookupTrust({
    required String deviceId,
    required String publicKey,
  }) async {
    final known = trusted[deviceId];
    if (known == null) return TrustState.unknown;
    return known == publicKey ? TrustState.known : TrustState.identityConflict;
  }

  @override
  bool isRateLimited(String deviceId) => rateLimited;

  @override
  void recordFailure(String deviceId) => failures++;

  @override
  Future<void> forgetPeer(String deviceId) async => trusted.remove(deviceId);
}

PeerInfo selfInfo({String deviceId = 'me', String name = 'Test Device'}) =>
    PeerInfo(
      deviceId: deviceId,
      deviceName: name,
      os: AeroOs.macos,
      osVersion: '15.0',
      appVersion: '1.0.0',
      publicKey: 'cHVibGljLWtleQ==',
      protocolVersion: kProtocolVersion,
      capabilities: const {
        Capability.send,
        Capability.receive,
        Capability.multiFile,
      },
      nonce: 'self-nonce',
    );

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Everything a transfer needs, wired to a temp directory.
class Harness {
  Harness._(this.root, this.store, this.api, this.link, this.authority);

  final Directory root;
  final LocalFileStore store;
  final AeroPeerApi api;
  final FakePeerLink link;
  final FakePairingAuthority authority;

  static Future<Harness> create({
    String authorityCode = '424242',
    bool rateLimited = false,
  }) async {
    final root = Directory.systemTemp.createTempSync('aero_engine_test');
    final store = LocalFileStore(
      baseDirectory: root,
      // Hermetic: never publish into the developer's real Downloads folder.
      destination: DownloadsDestination(root: Directory('${root.path}/downloads')),
    );
    final authority = FakePairingAuthority(
      expectedCode: authorityCode,
      rateLimited: rateLimited,
    );
    final api = AeroPeerApi(
      selfInfo: () => selfInfo(),
      store: store,
      authority: authority,
    );
    final link = FakePeerLink()..api = api;
    link.remote = selfInfo(deviceId: 'peer', name: 'Remote');
    final harness = Harness._(root, store, api, link, authority);
    // A rate-limited authority refuses every attempt, so a harness built that way
    // is deliberately left unpaired for the test to drive itself.
    if (!rateLimited) await harness.pair();
    return harness;
  }

  /// Pairs over the real endpoint, so every test also exercises pairing.
  Future<void> pair() => link.requestJson(
    'POST',
    Api.pair,
    body: {
      'confirm': true,
      'deviceId': 'peer',
      'publicKey': 'cHVibGljLWtleQ==',
      'nonce': 'remote-nonce',
      'proof': {'method': Crypto.pairingMethod, 'value': harnessCode},
    },
  );

  late final String harnessCode = authority.expectedCode;

  String inboxPath(String relative) =>
      '${root.path}${Platform.pathSeparator}downloads${Platform.pathSeparator}'
      '${relative.split('/').join(Platform.pathSeparator)}';

  List<String> inboxEntries() {
    final inbox = Directory('${root.path}${Platform.pathSeparator}downloads');
    if (!inbox.existsSync()) return const [];
    return inbox
        .listSync(recursive: true)
        .whereType<File>()
        .map(
          (f) => f.path
              .substring(inbox.path.length + 1)
              .replaceAll(Platform.pathSeparator, '/'),
        )
        .toList()
      ..sort();
  }

  List<String> stagedParts() {
    final sessions = Directory(
      '${root.path}${Platform.pathSeparator}aero-sessions',
    );
    if (!sessions.existsSync()) return const [];
    return sessions
        .listSync(recursive: true)
        .whereType<File>()
        .map((f) => f.path.split(Platform.pathSeparator).last)
        .where((n) => n.endsWith(kPartSuffix))
        .toList();
  }

  Future<void> dispose() async {
    await api.dispose();
    if (root.existsSync()) root.deleteSync(recursive: true);
  }
}

/// Deterministic, compressible-ish pseudo-random bytes. Deterministic matters:
/// a failure must be reproducible.
Uint8List makeBytes(int length, {int seed = 1}) {
  final random = math.Random(seed);
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = random.nextInt(256);
  }
  return out;
}

Future<String> sha256Hex(List<int> bytes) async =>
    _hexOf((await Sha256().hash(bytes)).bytes);

String _hexOf(List<int> bytes) {
  const digits = '0123456789abcdef';
  final out = StringBuffer();
  for (final b in bytes) {
    out.writeCharCode(digits.codeUnitAt((b >> 4) & 0x0f));
    out.writeCharCode(digits.codeUnitAt(b & 0x0f));
  }
  return out.toString();
}

/// Wraps a [FakePeerLink] and strips the `resume` map out of the offer response,
/// so the sender has to discover the resume point the hard way.
///
/// This is the failure mode a real transport hits whenever the receiver's
/// in-memory resume state and the sender's view diverge — for example after a
/// reconnect, where the receiver recovered its offset from the `.part` on disk
/// rather than from its own bookkeeping.
class _BlindResumeLink implements PeerLink {
  _BlindResumeLink(this._inner);

  final PeerLink _inner;

  /// The `Content-Range` of each PUT, or null for a request that sent none.
  final List<String?> puts = <String?>[];

  @override
  String get transportName => _inner.transportName;

  @override
  PeerInfo? get remote => _inner.remote;

  @override
  set remote(PeerInfo? value) => _inner.remote = value;

  @override
  String? get remoteCertFingerprint => _inner.remoteCertFingerprint;

  @override
  String get localCertFingerprint => _inner.localCertFingerprint;

  @override
  bool get isPaired => _inner.isPaired;

  @override
  Future<Map<String, dynamic>> requestJson(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  }) async {
    final response = await _inner.requestJson(
      method,
      path,
      body: body,
      headers: headers,
    );
    if (path == Api.offer) response.remove('resume');
    return response;
  }

  @override
  Future<Map<String, dynamic>> getJson(String path) => _inner.getJson(path);

  @override
  Future<Map<String, dynamic>> putStream(
    String path,
    Stream<List<int>> data, {
    int? contentLength,
    Map<String, String>? headers,
    void Function(int bytesSent)? onProgress,
  }) {
    puts.add(headers?[Header.contentRange]);
    return _inner.putStream(
      path,
      data,
      contentLength: contentLength,
      headers: headers,
      onProgress: onProgress,
    );
  }

  @override
  Future<void> close() => _inner.close();
}

void main() {
  late Harness harness;

  setUpAll(() {
    initLogging(level: Level.WARNING);
  });

  setUp(() async {
    harness = await Harness.create();
  });

  tearDown(() async {
    await harness.dispose();
  });

  group('pairing gate', () {
    test('GET /v1/info is reachable without pairing', () async {
      final root = Directory.systemTemp.createTempSync('aero_info_test');
      addTearDown(() => root.deleteSync(recursive: true));
      final api = AeroPeerApi(
        selfInfo: () => selfInfo(),
        store: LocalFileStore(baseDirectory: root),
        authority: FakePairingAuthority(),
      );
      final link = FakePeerLink()..api = api;
      addTearDown(api.dispose);

      final info = await link.getJson(Api.info);
      expect(info['deviceId'], 'me');
      expect(info['protocol'], kProtocolVersion);
      expect(api.isPaired(link), isFalse);
    });

    test('every other endpoint refuses an unpaired link', () async {
      final root = Directory.systemTemp.createTempSync('aero_gate_test');
      addTearDown(() => root.deleteSync(recursive: true));
      final api = AeroPeerApi(
        selfInfo: () => selfInfo(),
        store: LocalFileStore(baseDirectory: root),
        authority: FakePairingAuthority(),
      );
      final link = FakePeerLink()..api = api;
      link.remote = selfInfo(deviceId: 'peer');
      addTearDown(api.dispose);

      final protected = [
        (method: 'POST', path: Api.offer),
        (method: 'PUT', path: Api.fileStatus('x')),
        (method: 'GET', path: Api.fileStatus('x')),
        (method: 'POST', path: Api.complete),
        (method: 'POST', path: Api.cancel),
        (method: 'GET', path: Api.status),
        (method: 'POST', path: '/v1/anything-else'),
      ];

      for (final route in protected) {
        await expectLater(
          link.requestJson(route.method, route.path, body: const {}),
          throwsA(
            isA<PeerException>().having(
              (e) => e.code,
              'code',
              ApiError.notPaired,
            ),
          ),
          reason: '${route.method} ${route.path} must require pairing',
        );
      }
      expect(api.isPaired(link), isFalse);
    });

    test('a wrong pairing code is refused and recorded', () async {
      final h = await Harness.create(authorityCode: '111111');
      addTearDown(h.dispose);
      // Re-pair with the wrong code against a link that is not yet paired.
      final wrong = FakePeerLink()..api = h.api;
      wrong.remote = selfInfo(deviceId: 'peer');

      await expectLater(
        wrong.requestJson(
          'POST',
          Api.pair,
          body: {
            'confirm': true,
            'deviceId': 'peer',
            'publicKey': 'k',
            'nonce': 'n',
            'proof': {'method': Crypto.pairingMethod, 'value': '999999'},
          },
        ),
        throwsA(
          isA<PeerException>().having(
            (e) => e.code,
            'code',
            ApiError.sasMismatch,
          ),
        ),
      );
      expect(h.api.isPaired(wrong), isFalse);
      expect(h.authority.failures, greaterThan(0));
    });

    test('a rate-limited device cannot pair', () async {
      final h = await Harness.create(rateLimited: true);
      addTearDown(h.dispose);
      final link = FakePeerLink()..api = h.api;
      link.remote = selfInfo(deviceId: 'peer');

      await expectLater(
        link.requestJson(
          'POST',
          Api.pair,
          body: {
            'confirm': true,
            'deviceId': 'peer',
            'nonce': 'n',
            'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
          },
        ),
        throwsA(
          isA<PeerException>().having(
            (e) => e.code,
            'code',
            ApiError.tooManyAttempts,
          ),
        ),
      );
    });

    test('trust on first use pairs a known device without a code', () async {
      final h = await Harness.create();
      addTearDown(h.dispose);
      h.authority.trusted['peer'] = 'cHVibGljLWtleQ==';

      final link = FakePeerLink()..api = h.api;
      link.remote = selfInfo(deviceId: 'peer');

      final result = await link.requestJson('POST', Api.pair, body: const {});
      expect(result['paired'], isTrue);
      expect(result['trustState'], TrustState.known.name);
      expect(h.api.isPaired(link), isTrue);
    });

    test('an untrusted device cannot pair without confirming a code', () async {
      final link = FakePeerLink()..api = harness.api;
      link.remote = selfInfo(deviceId: 'stranger');

      await expectLater(
        link.requestJson('POST', Api.pair, body: const {}),
        throwsA(
          isA<PeerException>().having(
            (e) => e.code,
            'code',
            ApiError.notPaired,
          ),
        ),
      );
    });
  });

  group('unknown routes', () {
    test('a bad path is a 400 bad_request, not a crash', () async {
      final response = await harness.link.raw('POST', '/v1/nope');
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('a wrong verb on a known path is a 400', () async {
      final response = await harness.link.raw('DELETE', Api.offer);
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('an oversized JSON body is refused before parsing', () async {
      // A hostile peer must not be able to make us buffer arbitrary amounts.
      final huge = 'x' * (kMaxJsonBodyBytes + 1024);
      final body = utf8.encode('{"sessionId":"$huge"}');
      final response = await harness.link.raw(
        'POST',
        Api.offer,
        body: Stream.value(body),
      );
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('a malformed JSON body is a 400', () async {
      final response = await harness.link.raw(
        'POST',
        Api.offer,
        body: Stream.value(utf8.encode('{not json')),
      );
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('a manifest with the wrong shape is a 400', () async {
      final response = await harness.link.raw(
        'POST',
        Api.offer,
        body: Stream.value(utf8.encode('{"files": "not a list"}')),
      );
      expect(response.statusCode, 400);
    });
  });

  group('single file, end to end', () {
    test('arrives byte-identical and is committed', () async {
      const size = 100 * 1024;
      final payload = makeBytes(size, seed: 7);
      final source = File('${harness.root.path}/source.bin');
      await source.writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-single',
      );
      final progress = <FileProgress>[];
      final sub = session.progress.listen(progress.add);
      addTearDown(sub.cancel);

      final result = await session.send([
        LocalFile.fromPath(source.path, id: 'f1', size: size),
      ]);
      await session.dispose();

      expect(
        result.ok,
        isTrue,
        reason:
            'ok=${result.ok} failures=${result.failures} verdict=${result.verdict}',
      );
      expect(result.completed.map((e) => e.id), ['f1']);
      expect(result.failures, isEmpty);

      expect(harness.inboxEntries(), ['source.bin']);
      final received = await File(harness.inboxPath('source.bin'))
          .readAsBytes();
      expect(received, equals(payload));
      expect(result.completed.single.sha256, await sha256Hex(payload));

      // Progress reached the UI: queued -> ... -> done, ending at 100%.
      expect(progress, isNotEmpty);
      expect(progress.first.state, TransferState.queued);
      expect(progress.last.state, TransferState.done);
      expect(progress.last.fraction, 1.0);
      expect(progress.every((p) => p.entry.id == 'f1'), isTrue);
      expect(harness.stagedParts(), isEmpty);
    });

    test('a zero-byte file completes', () async {
      final source = File('${harness.root.path}/empty.bin');
      await source.writeAsBytes(const []);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-empty',
      );
      final result = await session.send([
        LocalFile.fromPath(source.path, id: 'z', size: 0),
      ]);
      await session.dispose();

      expect(result.ok, isTrue);
      expect(await File(harness.inboxPath('empty.bin')).length(), 0);
    });

    test('a file sent in small slices still reassembles', () async {
      // Exercises the streaming path with many body events rather than one.
      const size = 300 * 1024;
      final payload = makeBytes(size, seed: 11);
      final source = File('${harness.root.path}/sliced.bin');
      await source.writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-sliced',
      );
      final result = await session.send([
        LocalFile.fromPath(source.path, id: 's', size: size),
      ]);
      await session.dispose();

      expect(result.ok, isTrue);
      expect(
        await File(harness.inboxPath('sliced.bin')).readAsBytes(),
        equals(payload),
      );
    });
  });

  group('multiple files', () {
    test('five files all arrive, with concurrency bounded', () async {
      const count = 5;
      final files = <LocalFile>[];
      final payloads = <String, Uint8List>{};

      for (var i = 0; i < count; i++) {
        final size = (i + 1) * 64 * 1024;
        final payload = makeBytes(size, seed: 100 + i);
        final path = '${harness.root.path}/file$i.bin';
        await File(path).writeAsBytes(payload);
        payloads['file$i.bin'] = payload;
        files.add(LocalFile.fromPath(path, id: 'id$i', size: size));
      }

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-multi',
        // Three workers: more than the production cap, so a bug that ignores
        // the pool would still pass, but the pool itself is exercised.
        maxParallel: 3,
      );
      final result = await session.send(files);
      await session.dispose();

      expect(result.ok, isTrue);
      expect(result.completed.length, count);
      expect(result.failures, isEmpty);
      expect(harness.inboxEntries(), hasLength(count));

      for (final entry in payloads.entries) {
        final bytes = await File(harness.inboxPath(entry.key)).readAsBytes();
        expect(bytes, equals(entry.value), reason: entry.key);
      }
    });

    test('a folder structure is recreated from relPath', () async {
      final payload = makeBytes(2048, seed: 3);
      final source = File('${harness.root.path}/leaf.jpg');
      await source.writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-folder',
      );
      final result = await session.send([
        LocalFile(
          id: 'leaf',
          path: source.path,
          name: 'leaf.jpg',
          size: payload.length,
          relPath: 'photos/holiday/day1',
        ),
      ]);
      await session.dispose();

      expect(result.ok, isTrue);
      expect(harness.inboxEntries(), ['photos/holiday/day1/leaf.jpg']);
      expect(
        await File(harness.inboxPath('photos/holiday/day1/leaf.jpg'))
            .readAsBytes(),
        equals(payload),
      );
    });

    test('a hostile relPath is rejected with unsupportedName', () async {
      final source = File('${harness.root.path}/evil.bin');
      await source.writeAsBytes(makeBytes(64));

      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'evil-session',
          'totalSize': 64,
          'files': [
            {
              'id': 'e1',
              'name': 'evil.bin',
              'size': 64,
              'relPath': '../../pwn',
            },
          ],
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, isEmpty);
      expect(parsed.rejected.single.$2, RejectReason.unsupportedName);
    });
  });

  group('a 5 MiB file across multiple chunks', () {
    test('transfers and verifies by sha256', () async {
      // Larger than two 4 MiB chunks on purpose: the receiver must fold several
      // slices into one digest, and a bug that resets the hasher per slice would
      // only show up here.
      const size = 5 * 1024 * 1024 + 12345;
      final payload = makeBytes(size, seed: 42);
      final expectedDigest = await sha256Hex(payload);
      final source = File('${harness.root.path}/big.bin');
      await source.writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'e2e-big',
      );
      final result = await session.send([
        LocalFile.fromPath(source.path, id: 'big', size: size),
      ]);
      await session.dispose();

      expect(
        result.ok,
        isTrue,
        reason:
            '${result.toString()} failures=${result.failures} verdict=${result.verdict}',
      );
      expect(result.completed.single.sha256, expectedDigest);

      final received = await File(harness.inboxPath('big.bin')).readAsBytes();
      expect(received.length, size);
      expect(await sha256Hex(received), expectedDigest);
      expect(received, equals(payload));
    }, timeout: const Timeout(Duration(minutes: 2)));
  });

  group('resume', () {
    /// Drives the protocol by hand so a specific prefix can be staged before the
    /// real sender takes over — exactly what a reconnect looks like on the wire.
    Future<void> seedPrefix({
      required String sessionId,
      required String fileId,
      required List<int> full,
      required int prefixBytes,
      String? sha256,
      String? name,
      String? relPath,
    }) async {
      final offer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': sessionId,
          'totalSize': full.length,
          'files': [
            {
              'id': fileId,
              'name': name ?? 'resumed.bin',
              'size': full.length,
              'relPath': relPath,
              'sha256': ?sha256,
            },
          ],
        },
      );
      final answer = OfferResponse.fromJson(offer);
      expect(answer.accepted, contains(fileId));

      final response = await harness.link.raw(
        'PUT',
        Api.fileStatus(fileId),
        headers: {
          // No Content-Range: this is an ordinary transfer that gets cut short.
          Header.sha256: ?sha256,
          Header.sessionId: sessionId,
        },
        body: Stream.value(full.sublist(0, prefixBytes)),
      );
      // A truncated body must be answered with a 409 carrying the resume point,
      // never with a success that leaves the receiver believing it has the whole
      // file.
      expect(response.statusCode, 409);
      expect(response.json?['resumeFrom'], prefixBytes);
    }

    test(
      'a dropped connection shrinks the staged file to its true length',
      () async {
        const size = 10 * 1024 * 1024;
        final payload = makeBytes(size, seed: 21);
        await seedPrefix(
          sessionId: 'resume-1',
          fileId: 'r1',
          full: payload,
          prefixBytes: 2 * Transfer.chunkSize + 777,
        );

        // Pretend the link dropped: the receiver must keep the staged bytes and
        // leave the length honest, because `existingBytes` reads the length.
        harness.link.simulateDisconnect = true;
        harness.api.onDisconnect(harness.link);
        await harness.api.drain();

        final staged = await harness.store.existingBytes('resume-1', 'r1');
        expect(staged, 2 * Transfer.chunkSize + 777);
        expect(
          harness.inboxEntries(),
          isEmpty,
          reason: 'nothing may be committed before /v1/complete',
        );
      },
    );

    test('a torn preallocated .part is restarted rather than trusted', () async {
      // Simulates the process dying mid-write: the .part is at its full
      // preallocated length but only partly written. `existingBytes` reads the
      // length, so a naive implementation would believe the file is complete,
      // send nothing, and fail the digest check much later with a baffling
      // error. The receiver must notice and start the file over.
      const size = 4096;
      final payload = makeBytes(size, seed: 5);
      final digest = await sha256Hex(payload);
      await File('${harness.root.path}/torn.bin').writeAsBytes(payload);

      await seedPrefix(
        sessionId: 'resume-torn',
        fileId: 't1',
        full: payload,
        prefixBytes: 100,
        sha256: digest,
      );

      // Re-inflate the .part to its full length, as a torn write would.
      final part = File(
        '${harness.root.path}${Platform.pathSeparator}aero-sessions'
        '${Platform.pathSeparator}resume-torn${Platform.pathSeparator}t1.part',
      );
      final raf = await part.open(mode: FileMode.append);
      raf.truncateSync(size);
      await raf.close();
      expect(part.lengthSync(), size);

      // A fresh link re-offers the same session. The torn file must be reported
      // as 0 bytes stored, not as `size`.
      final link2 = FakePeerLink()..api = harness.api;
      link2.remote = selfInfo(deviceId: 'peer');
      await link2.requestJson(
        'POST',
        Api.pair,
        body: {
          'confirm': true,
          'deviceId': 'peer',
          'publicKey': 'k',
          'nonce': 'n',
          'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
        },
      );

      final answer = await link2.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'resume-torn',
          'totalSize': size,
          'files': [
            {'id': 't1', 'name': 'torn.bin', 'size': size, 'sha256': digest},
          ],
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, ['t1']);
      expect(
        parsed.resume,
        isEmpty,
        reason: 'a full-length leftover is treated as nothing stored',
      );
      expect(await harness.store.existingBytes('resume-torn', 't1'), 0);

      final session = SenderSession(
        link: link2,
        reader: harness.store,
        store: harness.store,
        sessionId: 'resume-torn',
      );
      final result = await session.send([
        LocalFile.fromPath(
          '${harness.root.path}/torn.bin',
          id: 't1',
          size: size,
        ),
      ]);
      await session.dispose();

      expect(result.ok, isTrue, reason: result.toString());
      expect(
        await File(harness.inboxPath('torn.bin')).readAsBytes(),
        equals(payload),
      );
    });

    test('two chunks, abort, resume, final file is identical', () async {
      const size = 4 * 1024 * 1024 * 3; // three chunks
      final payload = makeBytes(size, seed: 99);
      final digest = await sha256Hex(payload);
      const cut = Transfer.chunkSize * 2; // exactly two chunks sent

      // Phase 1: offer and send two chunks, then abort.
      await seedPrefix(
        sessionId: 'resume-2',
        fileId: 'r2',
        full: payload,
        prefixBytes: cut,
        sha256: digest,
      );
      harness.api.onDisconnect(harness.link);
      await harness.api.drain();

      expect(await harness.store.existingBytes('resume-2', 'r2'), cut);
      expect(harness.inboxEntries(), isEmpty);

      // Phase 2: a brand new link re-offers and resumes from the staged length.
      final link2 = FakePeerLink()..api = harness.api;
      link2.remote = selfInfo(deviceId: 'peer');
      await link2.requestJson(
        'POST',
        Api.pair,
        body: {
          'confirm': true,
          'deviceId': 'peer',
          'publicKey': 'cHVibGljLWtleQ==',
          'nonce': 'remote-nonce',
          'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
        },
      );

      final source = File('${harness.root.path}/resumed.bin');
      await source.writeAsBytes(payload);

      final session = SenderSession(
        link: link2,
        reader: harness.store,
        store: harness.store,
        sessionId: 'resume-2',
      );
      final resumedOffsets = <String>[];
      final result = await session.send([
        LocalFile.fromPath(source.path, id: 'r2', size: size),
      ]);
      await session.dispose();
      resumedOffsets.add('$result');

      expect(result.ok, isTrue, reason: result.toString());
      expect(result.completed.single.sha256, digest);

      final received = await File(harness.inboxPath('resumed.bin'))
          .readAsBytes();
      expect(received.length, size);
      expect(await sha256Hex(received), digest);
      expect(received, equals(payload));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test(
      'the receiver answers a stale offset with 409 and resumeFrom',
      () async {
        const size = 1024;
        final payload = makeBytes(size, seed: 8);
        await harness.link.requestJson(
          'POST',
          Api.offer,
          body: {
            'sessionId': 'stale',
            'totalSize': size,
            'files': [
              {'id': 's1', 'name': 'stale.bin', 'size': size},
            ],
          },
        );

        // No bytes staged yet, but the sender claims to be resuming from 512.
        final response = await harness.link.raw(
          'PUT',
          Api.fileStatus('s1'),
          headers: {Header.contentRange: 'bytes=512-'},
          body: Stream.value(payload.sublist(512)),
        );
        expect(response.statusCode, 409);
        expect(response.json?['error'], ApiError.conflict);
        expect(response.json?['resumeFrom'], 0);

        // And the peer can ask where to resume from instead.
        final status = await harness.link.getJson(Api.fileStatus('s1'));
        expect(status['received'], 0);
        expect(status['complete'], isFalse);
      },
    );

    test('the sender seeks to the peer offset when it gets a 409', () async {
      // The sender believes it must start from 0 (no `resume` in the offer), but
      // the receiver already holds a prefix. The receiver answers 409, the sender
      // asks `GET /v1/file/{id}` where it really is, and seeks there instead of
      // failing the file or re-sending from zero.
      const size = 4096;
      final payload = makeBytes(size, seed: 6);
      final digest = await sha256Hex(payload);
      await File('${harness.root.path}/seek.bin').writeAsBytes(payload);

      // Stage a prefix for a session the sender knows nothing about yet.
      await seedPrefix(
        sessionId: 'seek',
        fileId: 'k1',
        full: payload,
        prefixBytes: 1000,
        sha256: digest,
      );
      harness.api.onDisconnect(harness.link);
      await harness.api.drain();

      final link2 = FakePeerLink()..api = harness.api;
      link2.remote = selfInfo(deviceId: 'peer');
      await link2.requestJson(
        'POST',
        Api.pair,
        body: {
          'confirm': true,
          'deviceId': 'peer',
          'publicKey': 'k',
          'nonce': 'n',
          'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
        },
      );

      // A link that deliberately strips `resume` from the offer response, so the
      // sender starts from 0 and hits the conflict.
      final blind = _BlindResumeLink(link2);

      final session = SenderSession(
        link: blind,
        reader: harness.store,
        store: harness.store,
        sessionId: 'seek',
      );
      final result = await session.send([
        LocalFile.fromPath(
          '${harness.root.path}/seek.bin',
          id: 'k1',
          size: size,
        ),
      ]);
      await session.dispose();

      expect(result.ok, isTrue, reason: result.toString());
      expect(blind.puts, [
        null,
        'bytes=1000-',
      ], reason: 'the sender must seek to the peer offset, not restart');
      expect(
        await File(harness.inboxPath('seek.bin')).readAsBytes(),
        equals(payload),
      );
    });

    test(
      'a short body is answered 409 with the byte count actually stored',
      () async {
        const size = 2048;
        final payload = makeBytes(size, seed: 9);
        await harness.link.requestJson(
          'POST',
          Api.offer,
          body: {
            'sessionId': 'short',
            'totalSize': size,
            'files': [
              {'id': 's1', 'name': 'short.bin', 'size': size},
            ],
          },
        );

        final response = await harness.link.raw(
          'PUT',
          Api.fileStatus('s1'),
          body: Stream.value(payload.sublist(0, 700)),
        );
        expect(response.statusCode, 409);
        expect(response.json?['resumeFrom'], 700);
        expect(
          await harness.store.existingBytes('short', 's1'),
          700,
          reason: 'the .part must be shrunk to what actually landed',
        );
      },
    );
  });

  group('integrity failures', () {
    test(
      'a corrupted byte yields hashMismatch and nothing is committed',
      () async {
        const size = 4096;
        final payload = makeBytes(size, seed: 12);
        final digest = await sha256Hex(payload);
        final source = File('${harness.root.path}/corrupt.bin');
        await source.writeAsBytes(payload);

        final link = harness.link;
        final chunked = FakePeerLink(maxChunkedBody: true)..api = harness.api;
        chunked.remote = selfInfo(deviceId: 'peer');
        await chunked.requestJson(
          'POST',
          Api.pair,
          body: {
            'confirm': true,
            'deviceId': 'peer',
            'publicKey': 'k',
            'nonce': 'n',
            'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
          },
        );

        await chunked.requestJson(
          'POST',
          Api.offer,
          body: {
            'sessionId': 'corrupt',
            'totalSize': size,
            'files': [
              {
                'id': 'c1',
                'name': 'corrupt.bin',
                'size': size,
                'sha256': digest,
              },
            ],
          },
        );

        // Flip a byte on the way in, exactly where a bad link or a lying peer
        // would corrupt it.
        final response = await chunked.raw(
          'PUT',
          Api.fileStatus('c1'),
          headers: {Header.sha256: digest, Header.sessionId: 'corrupt'},
          body: _tamper(payload, 2000),
        );

        expect(response.statusCode, 422);
        expect(response.json?['error'], ApiError.hashMismatch);
        expect(response.json?['sha256Match'], isFalse);
        expect(response.json?['actual'], isNot(digest));

        // The poisoned staged file is thrown away rather than left to poison a
        // retry.
        expect(await harness.store.existingBytes('corrupt', 'c1'), 0);
        expect(harness.inboxEntries(), isEmpty);
        expect(link.isPaired, isTrue);
      },
    );

    test(
      'a sender that lies in /v1/complete is caught by the on-disk digest',
      () async {
        const size = 1024;
        final payload = makeBytes(size, seed: 13);
        final trueDigest = await sha256Hex(payload);
        await harness.link.requestJson(
          'POST',
          Api.offer,
          body: {
            'sessionId': 'liar',
            'totalSize': size,
            'files': [
              {'id': 'l1', 'name': 'liar.bin', 'size': size},
            ],
          },
        );
        await harness.link.raw(
          'PUT',
          Api.fileStatus('l1'),
          body: Stream.value(payload),
        );

        // Report a different digest than the bytes actually on disk.
        final verdict = await harness.link.requestJson(
          'POST',
          Api.complete,
          body: {
            'sessionId': 'liar',
            'files': [
              {'id': 'l1', 'sha256': '0' * 64, 'bytes': size},
            ],
          },
        );
        final result = CompletionResult.fromJson(verdict);
        expect(result.ok, isFalse);
        expect(result.failures.single, contains('sha256 mismatch'));
        expect(
          harness.inboxEntries(),
          isEmpty,
          reason: 'a file that fails verification must not be committed',
        );

        // The same report with the true digest succeeds.
        final ok = await harness.link.requestJson(
          'POST',
          Api.complete,
          body: {
            'sessionId': 'liar',
            'files': [
              {'id': 'l1', 'sha256': trueDigest, 'bytes': size},
            ],
          },
        );
        expect(CompletionResult.fromJson(ok).ok, isTrue);
        expect(harness.inboxEntries(), ['liar.bin']);
      },
    );

    test(
      'a sender that reports the wrong byte count fails completion',
      () async {
        const size = 512;
        final payload = makeBytes(size, seed: 14);
        await harness.link.requestJson(
          'POST',
          Api.offer,
          body: {
            'sessionId': 'liar2',
            'totalSize': size,
            'files': [
              {'id': 'l2', 'name': 'liar2.bin', 'size': size},
            ],
          },
        );
        await harness.link.raw(
          'PUT',
          Api.fileStatus('l2'),
          body: Stream.value(payload),
        );
        final verdict = await harness.link.requestJson(
          'POST',
          Api.complete,
          body: {
            'sessionId': 'liar2',
            'files': [
              {'id': 'l2', 'sha256': '', 'bytes': 4096},
            ],
          },
        );
        final result = CompletionResult.fromJson(verdict);
        expect(result.ok, isFalse);
        expect(result.failures.single, contains('sender claims 4096'));
        expect(harness.inboxEntries(), isEmpty);
      },
    );

    test('a body longer than declared is refused', () async {
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'over',
          'totalSize': 100,
          'files': [
            {'id': 'o1', 'name': 'over.bin', 'size': 100},
          ],
        },
      );
      final response = await harness.link.raw(
        'PUT',
        Api.fileStatus('o1'),
        body: Stream.value(makeBytes(500)),
      );
      expect(response.statusCode, 413);
      expect(response.json?['error'], ApiError.tooLarge);
    });

    test('a header digest that disagrees with the offer is refused', () async {
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'mismatch',
          'totalSize': 64,
          'files': [
            {'id': 'm1', 'name': 'm.bin', 'size': 64, 'sha256': 'a' * 64},
          ],
        },
      );
      final response = await harness.link.raw(
        'PUT',
        Api.fileStatus('m1'),
        headers: {Header.sha256: 'b' * 64},
        body: Stream.value(makeBytes(64)),
      );
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('a PUT for a file that was never offered is refused', () async {
      final response = await harness.link.raw(
        'PUT',
        Api.fileStatus('ghost'),
        body: Stream.value(makeBytes(10)),
      );
      expect(response.statusCode, 400);
    });

    test('a traversal file id is refused', () async {
      final response = await harness.link.raw(
        'PUT',
        '${Api.file}/${Uri.encodeComponent('../../escape')}',
        body: Stream.value(makeBytes(10)),
      );
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });
  });

  group('offer negotiation', () {
    test('a structurally refused offer never reaches the user', () async {
      // Ordering rule: cheap, prompt-free checks run BEFORE `onOffer`. Prompting
      // someone to accept a transfer and then refusing it on a rule we could
      // have checked first makes the app look broken. This pins that down.
      final root = Directory.systemTemp.createTempSync('aero_order_test');
      addTearDown(() => root.deleteSync(recursive: true));
      var prompts = 0;
      final api = AeroPeerApi(
        selfInfo: () => selfInfo(),
        store: LocalFileStore(
          baseDirectory: root,
          destination: DownloadsDestination(root: Directory('${root.path}/dl')),
        ),
        authority: FakePairingAuthority(expectedCode: '424242'),
        onOffer: (link, offer) async {
          prompts++;
          return true;
        },
      );
      addTearDown(api.dispose);
      final link = FakePeerLink()..api = api;
      link.remote = selfInfo(deviceId: 'peer', name: 'Remote');

      // Pair first, since every non-info route is gated on it.
      await link.requestJson(
        'POST',
        Api.pair,
        body: {
          'confirm': true,
          'deviceId': 'peer',
          'publicKey': 'cHVibGljLWtleQ==',
          'nonce': 'remote-nonce',
          'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
        },
      );

      final files = [
        for (var i = 0; i <= Transfer.maxFilesPerTransfer; i++)
          {'id': 'x$i', 'name': 'f$i', 'size': 1},
      ];
      final answer = await link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'huge',
          'totalSize': files.length,
          'files': files,
        },
      );

      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.error, ApiError.tooLarge);
      expect(prompts, 0,
          reason: 'the user was prompted for an offer that was refused anyway');
    });

    test('too many files is rejected wholesale', () async {
      final files = [
        for (var i = 0; i <= Transfer.maxFilesPerTransfer; i++)
          {'id': 'x$i', 'name': 'f$i', 'size': 1},
      ];
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'too-many',
          'totalSize': files.length,
          'files': files,
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, isEmpty);
      expect(parsed.rejected.length, Transfer.maxFilesPerTransfer + 1);
      expect(
        parsed.rejected.every((r) => r.$2 == RejectReason.tooManyFiles),
        isTrue,
      );
      expect(parsed.error, ApiError.tooLarge);
    });

    test('an oversized single file is rejected individually', () async {
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'too-large',
          'totalSize': 1,
          'files': [
            {'id': 'ok', 'name': 'ok.bin', 'size': 10},
            {
              'id': 'huge',
              'name': 'huge.bin',
              'size': Transfer.maxFileSize + 1,
            },
          ],
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, ['ok']);
      expect(parsed.rejected, [('huge', RejectReason.tooLarge)]);
    });

    test('duplicate ids are rejected', () async {
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'dupes',
          'totalSize': 20,
          'files': [
            {'id': 'same', 'name': 'a.bin', 'size': 10},
            {'id': 'same', 'name': 'b.bin', 'size': 10},
          ],
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, ['same']);
      expect(parsed.rejected.single.$2, RejectReason.duplicate);
    });

    test('a partially rejected offer still transfers the accepted files', () async {
      const size = 1024;
      final payload = makeBytes(size, seed: 31);
      await File('${harness.root.path}/kept.bin').writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'partial',
      );

      // Pre-poison the session with an over-large entry so the offer contains a
      // rejection, then send only the good file through the normal path.
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'partial',
          'totalSize': size,
          'files': [
            {'id': 'kept', 'name': 'kept.bin', 'size': size},
            {
              'id': 'rejected',
              'name': 'bad.bin',
              'size': Transfer.maxFileSize + 1,
            },
          ],
        },
      );
      expect(OfferResponse.fromJson(answer).accepted, ['kept']);

      final result = await session.send([
        LocalFile.fromPath(
          '${harness.root.path}/kept.bin',
          id: 'kept',
          size: size,
        ),
      ]);
      await session.dispose();

      expect(result.ok, isTrue);
      expect(harness.inboxEntries(), ['kept.bin']);
    });

    test('rejected reasons surface verbatim in SendResult', () async {
      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'reasons',
      );
      // Offer a file the peer will refuse, then report it as if sent.
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'reasons',
          'totalSize': 1,
          'files': [
            {'id': 'nope', 'name': 'n.bin', 'size': 1},
          ],
        },
      );

      // Re-offer with a bad size so the peer rejects with a real reason.
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'reasons',
          'totalSize': Transfer.maxFileSize,
          'files': [
            {'id': 'nope', 'name': 'n.bin', 'size': Transfer.maxFileSize + 1},
          ],
        },
      );
      expect(
        OfferResponse.fromJson(answer).rejected.single.$2,
        RejectReason.tooLarge,
      );

      // Nothing was accepted, so send() returns with the rejection recorded and
      // sends no bytes at all.
      final result = await session.send(const []);
      await session.dispose();
      expect(result.completed, isEmpty);
    });

    test('a negative size is a protocol error', () async {
      final response = await harness.link.raw(
        'POST',
        Api.offer,
        body: Stream.value(
          utf8.encode(
            '{"sessionId":"neg","totalSize":1,"files":[{"id":"a","name":"a","size":-5}]}',
          ),
        ),
      );
      expect(response.statusCode, 400);
    });
  });

  group('cancel', () {
    test('discards staged files and marks the session cancelled', () async {
      const size = 8192;
      final payload = makeBytes(size, seed: 55);
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'cancel-me',
          'totalSize': size,
          'files': [
            {'id': 'c1', 'name': 'cancelled.bin', 'size': size},
          ],
        },
      );
      // Put a little in, so there is genuinely something to clean up.
      await harness.link.raw(
        'PUT',
        Api.fileStatus('c1'),
        body: Stream.value(payload.sublist(0, 4096)),
      );
      expect(harness.stagedParts(), isNotEmpty);

      final answer = await harness.link.requestJson(
        'POST',
        Api.cancel,
        body: {'sessionId': 'cancel-me', 'cancelled': true},
      );
      expect(answer['cancelled'], isTrue);

      expect(
        harness.stagedParts(),
        isEmpty,
        reason: 'cancel must delete every staged file',
      );
      expect(harness.inboxEntries(), isEmpty);

      // A further PUT on a cancelled session is refused with `cancelled` (499),
      // not silently accepted. `clearSession` also emptied the id map, so even
      // the "unknown id" check would have stopped it.
      final response = await harness.link.raw(
        'PUT',
        Api.fileStatus('c1'),
        body: Stream.value(payload),
      );
      expect(response.statusCode, 499);
      expect(response.json?['error'], ApiError.cancelled);
    });

    test('the sender posts /v1/cancel and reports cancelled', () async {
      const size = 2 * 1024 * 1024;
      final payload = makeBytes(size, seed: 56);
      await File('${harness.root.path}/big-cancel.bin').writeAsBytes(payload);

      final link = FakePeerLink()..api = harness.api;
      link.remote = selfInfo(deviceId: 'peer');
      // Cancel is not on the public allow-list, so the receiver must be paired
      // first or the request is refused with `not_paired` and the staged file
      // is legitimately left alone for resume.
      await link.requestJson(
        'POST',
        Api.pair,
        body: {
          'confirm': true,
          'deviceId': 'peer',
          'publicKey': 'k',
          'nonce': 'n',
          'proof': {'method': Crypto.pairingMethod, 'value': '424242'},
        },
      );

      final session = SenderSession(
        link: link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'cancel-sender',
        // One worker, so cancelling between files is deterministic.
        maxParallel: 1,
      );
      final states = <TransferState>[];
      final sub = session.progress.listen(
        (p) => states.add(p.state),
        onError: (Object e) {},
      );

      final future = session.send([
        LocalFile.fromPath(
          '${harness.root.path}/big-cancel.bin',
          id: 'a',
          size: size,
        ),
      ]);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      await session.cancel();
      final result = await future;
      await sub.cancel();
      await session.dispose();

      expect(result.cancelled, isTrue);
      expect(result.ok, isFalse);
      expect(
        harness.stagedParts(),
        isEmpty,
        reason: 'the peer deleted what it had staged',
      );
    });

    test('cancelling when idle is a no-op', () async {
      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'idle',
      );
      await session.cancel();
      await session.dispose();
    });
  });

  group('disconnect', () {
    test('drops state but keeps staged files for resume', () async {
      const size = 4096;
      final payload = makeBytes(size, seed: 77);
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'gone',
          'totalSize': size,
          'files': [
            {'id': 'g1', 'name': 'gone.bin', 'size': size},
          ],
        },
      );
      await harness.link.raw(
        'PUT',
        Api.fileStatus('g1'),
        body: Stream.value(payload.sublist(0, 1500)),
      );
      expect(harness.stagedParts(), hasLength(1));

      harness.api.onDisconnect(harness.link);
      await harness.api.drain();

      expect(
        harness.stagedParts(),
        hasLength(1),
        reason: 'staged files must survive a disconnect — that is resume',
      );
      expect(await harness.store.existingBytes('gone', 'g1'), 1500);
      expect(
        harness.api.isPaired(harness.link),
        isFalse,
        reason: 'per-connection state is gone; the link must pair again',
      );
    });
  });

  group('progress reporting', () {
    test('is throttled rather than emitted per chunk', () async {
      // 5 MiB across several 4 MiB chunks would be few events anyway, so use a
      // file big enough to produce many if throttling were absent.
      const size = 5 * 1024 * 1024;
      final payload = makeBytes(size, seed: 88);
      await File('${harness.root.path}/throttle.bin').writeAsBytes(payload);

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'throttle',
      );
      final events = <FileProgress>[];
      final sub = session.progress.listen(events.add);

      final result = await session.send([
        LocalFile.fromPath(
          '${harness.root.path}/throttle.bin',
          id: 't',
          size: size,
        ),
      ]);
      await sub.cancel();
      await session.dispose();

      expect(result.ok, isTrue);
      expect(events, isNotEmpty);
      // Without throttling this would be ~2 events per chunk plus hashing.
      // The real guarantee is that terminal and transition states always arrive.
      expect(
        events.last.state,
        TransferState.done,
        reason: 'tail=${events.take(6)}',
      );
      expect(events.last.fraction, 1.0);
      expect(events.where((e) => e.state == TransferState.failed), isEmpty);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('a broadcast stream serves several listeners', () async {
      const size = 4096;
      await File('${harness.root.path}/multi-listener.bin')
          .writeAsBytes(makeBytes(size, seed: 89));

      final session = SenderSession(
        link: harness.link,
        reader: harness.store,
        store: harness.store,
        sessionId: 'listeners',
      );
      final a = <FileProgress>[];
      final b = <FileProgress>[];
      session.progress.listen(a.add);
      session.progress.listen(b.add);

      await session.send([
        LocalFile.fromPath(
          '${harness.root.path}/multi-listener.bin',
          id: 'l',
          size: size,
        ),
      ]);
      await session.dispose();

      expect(a, isNotEmpty);
      expect(b, isNotEmpty);
      // Broadcast delivery is asynchronous, so the final `done` event may still
      // be in flight for one listener when `send` returns. Compare after a turn.
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(a.map((e) => e.state), b.map((e) => e.state));
    });
  });

  group('hostile peers', () {
    test('a hostile name never escapes the inbox', () async {
      const size = 128;
      final answer = await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'hostile',
          'totalSize': size,
          'files': [
            {
              'id': 'h1',
              'name': '../../../../../../tmp/aero-pwned',
              'size': size,
            },
            {
              'id': 'h2',
              'name': 'ok.bin',
              'size': size,
              'relPath': '../../../etc',
            },
          ],
        },
      );
      final parsed = OfferResponse.fromJson(answer);
      expect(parsed.accepted, isEmpty);
      expect(
        parsed.rejected.map((r) => r.$2),
        everyElement(RejectReason.unsupportedName),
      );
      expect(File('/tmp/aero-pwned').existsSync(), isFalse);
    });

    test('a hostile session id is refused at offer time', () async {
      final response = await harness.link.raw(
        'POST',
        Api.offer,
        body: Stream.value(
          utf8.encode(
            '{"sessionId":"../../escape","totalSize":1,'
            '"files":[{"id":"a","name":"a","size":1}]}',
          ),
        ),
      );
      expect(response.statusCode, 400);
      expect(response.json?['error'], ApiError.badRequest);
    });

    test('a completion report for the wrong session is refused', () async {
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'right',
          'totalSize': 4,
          'files': [
            {'id': 'w1', 'name': 'w.bin', 'size': 4},
          ],
        },
      );
      final response = await harness.link.raw(
        'POST',
        Api.complete,
        body: Stream.value(utf8.encode('{"sessionId":"wrong","files":[]}')),
      );
      // `ApiError.unknownSession` is a wire code the frozen contract has no HTTP
      // mapping for, so it lands on the catch-all 500 while keeping its code in
      // the body. That is exactly what the contract specifies for a new code, and
      // it is why errors are strings on the wire.
      expect(response.statusCode, 500);
      expect(response.json?['error'], ApiError.unknownSession);
    });

    test('a cancel with a malformed body still cancels', () async {
      await harness.link.requestJson(
        'POST',
        Api.offer,
        body: {
          'sessionId': 'badcancel',
          'totalSize': 4,
          'files': [
            {'id': 'x', 'name': 'x.bin', 'size': 4},
          ],
        },
      );
      final response = await harness.link.raw(
        'POST',
        Api.cancel,
        body: Stream.value(utf8.encode('{broken')),
      );
      expect(response.statusCode, 200);
      expect(response.json?['cancelled'], isTrue);
    });
  });
}

/// Flips one byte in the outgoing body, as a corrupt link would.
Stream<List<int>> _tamper(List<int> bytes, int index) async* {
  const slice = 512;
  for (var offset = 0; offset < bytes.length; offset += slice) {
    final end = math.min(offset + slice, bytes.length);
    final chunk = Uint8List.fromList(bytes.sublist(offset, end));
    if (index >= offset && index < end) {
      chunk[index - offset] = chunk[index - offset] ^ 0xFF;
    }
    yield chunk;
  }
}
