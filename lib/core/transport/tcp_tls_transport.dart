/// The Aero wire transport: TLS over TCP, speaking HTTP/1.1.
///
/// Why HTTP instead of hand-rolled framing: `dart:io` ships a HTTP/1.1
/// implementation on every target we support, and - decisively - it gives us
/// **backpressure** on request bodies for free. `ApiRequest.body` is the live
/// `HttpRequest` stream, so `PUT /v1/file` of a 40 GiB file is consumed at the
/// speed the receiver writes it to disk, and at most one [Transfer.chunkSize]
/// is ever in memory. See [TcpPeerLink.putStream].
///
/// ---------------------------------------------------------------------------
/// TLS posture - read this before "fixing" the certificate checks
/// ---------------------------------------------------------------------------
/// Aero uses **ephemeral, self-signed, single-use** certificates, minted per
/// session by [DeviceIdentity.beginSession] and discarded with the process.
/// There is no CA, no chain, and nothing to pin across launches. PKI
/// validation here is not "weak", it is *meaningless*: it could only ever be
/// satisfied by the platform trust store, which by construction never contains
/// our certificates, so enabling it would make every peer unreachable.
///
/// What replaces it is the six-digit short authentication string (SAS): both
/// devices independently derive the same six digits from *their own* view of
/// the two certificate fingerprints and a human checks that the digits match.
/// A man-in-the-middle necessarily terminates TLS twice, with two different
/// keys of its own, so its digits cannot match either device's - the model
/// Bluetooth and Zigbee use.
///
/// Hence [TcpPeerLink]'s `badCertificateCallback` returns `true` for every
/// certificate. That reads like a catastrophic downgrade and is in fact the
/// design: the channel is authenticated by the SAS, and the fingerprint that
/// SAS is derived from is read out of TLS - [X509Certificate.der] inside the
/// callback, [SecureSocket.peerCertificate] after the handshake,
/// [HttpClientResponse.certificate] per response - never from anything the peer
/// asserts about itself. One asymmetry is forced on us by dart:io and is
/// documented at length in [kCertFingerprintHeader].
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';

/// Header carrying the SHA-256 fingerprint (lowercase hex) of the *sender's*
/// ephemeral certificate.
///
/// **This belongs in `Header` in lib/core/constants.dart**, which is a frozen
/// contract this file must not modify, so it is declared here for now. The
/// pairing layer should import it from here rather than invent a spelling.
///
/// ### Why it exists - important, and it affects the SAS
///
/// dart:io *can* hand a server the client's certificate, two ways:
/// [HttpRequest.certificate] and (better) [SecureSocket.peerCertificate] on
/// the socket we intercept in [_ObservedServerSocket]. But only under one
/// condition: `requestPeerCertificate` must be on **and** the client's
/// certificate must chain to something in our trust store. Aero's certificates
/// are self-signed and unique per session, so they chain to nothing, which
/// leaves exactly two outcomes (both measured on macOS / Dart 3.13):
///
///   * `requestPeerCertificate: false` (the default) - handshake succeeds and
///     no certificate is available. This is what actually happens.
///   * `requestPeerCertificate: true` - BoringSSL runs `SSL_VERIFY_PEER`,
///     rejects the unverifiable client certificate, and **aborts the
///     handshake**. No peer can connect at all. Not "no certificate", "no
///     connection": the TLS alert arrives before the client sees Finished, and
///     in TLS 1.3 the client is happy right up until the first byte of HTTP
///     arrives.
///   * `trustedPeerCertificatePems` non-empty - the handshake succeeds *and* the
///     real certificate is handed over, so the serving side's fingerprint is
///     verified. This is the only configuration that keeps the whole promise of
///     [PeerLink.remoteCertFingerprint], and it needs a certificate to pin,
///     which trust on first use has to supply.
///
/// So a server-side link cannot read the real client certificate by default, and
/// falls back to what the client asserts in this header, flagged by
/// [TcpPeerLink.remoteCertFingerprintIsVerified] == `false`.
///
/// ### What that costs, precisely
///
/// A man-in-the-middle can lie to the *server* about the client's fingerprint,
/// because it controls the bytes on that connection. It still cannot produce a
/// matching SAS: the *client* derives its six digits from the certificate it
/// really terminated TLS with, and that certificate belongs to the
/// man-in-the-middle, so the two screens show different digits and the user
/// sees a mismatch. MITM detection survives; what the server displays is simply
/// no longer evidence on its own.
///
/// The clean fix is application-layer key confirmation: have the client sign a
/// server nonce with its *session* private key and bind the asserted
/// fingerprint into the signed payload, which turns the assertion into proof.
/// That belongs to the pairing layer - it owns [DeviceIdentity.sign] and the
/// wire format - and this transport deliberately does not invent protocol on
/// its own.
const String kCertFingerprintHeader = 'x-aero-cert';

/// Identity headers sent on every outbound request.
///
/// An inbound connection has no outbound `GET /v1/info` of its own, so without
/// these the receiving side knows nothing about the caller — not even the
/// nonce needed to derive the pairing code — and the SAS would be computed over
/// an empty value, guaranteeing a mismatch.
///
/// These are self-asserted and therefore untrusted for *authentication*: the
/// code still comes from the certificate fingerprint TLS proved, and a human
/// compares it. They exist so the two sides can derive the same number at all.
const String kDeviceNameHeader = 'x-aero-name';
const String kDeviceNonceHeader = 'x-aero-nonce';
const String kDevicePublicKeyHeader = 'x-aero-pubkey';
const String kDeviceOsHeader = 'x-aero-os';

/// Default budget for [TcpTlsTransport.connect]: TCP connect, TLS handshake and
/// the `GET /v1/info` exchange combined.
///
/// Eight seconds is deliberately generous. On a LAN the whole exchange takes
/// milliseconds, so the budget only has to survive a phone waking from sleep or
/// a Wi-Fi roam. Failing slowly is much better UX than failing spuriously.
const Duration kDefaultConnectTimeout = Duration(seconds: 8);

/// How long an idle keep-alive connection is held open before the socket is
/// recycled. dart:io defaults to two minutes, which is fine for request/response
/// but wrong for us: a user who walks away from a paused transfer and comes
/// back ten minutes later would silently lose the socket and its progress.
const Duration kIdleTimeout = Duration(minutes: 5);

/// TLS over TCP, HTTP/1.1 on top. One instance per device, serving and dialing
/// at the same time.
///
/// Lifecycle: [serve] zero or one times (once bound, [boundPort] is valid and
/// discovery may advertise it), [connect] any number of times, [close] once.
/// [close] is idempotent and safe to call concurrently.
///
/// [close] is terminal: the transport cannot be re-bound afterwards, because the
/// app must not keep advertising a port it has released. Construct a new one -
/// on mobile that is cheap, and it is the only way to guarantee a fresh
/// certificate for a fresh listening session.
class TcpTlsTransport implements PeerTransport {
  TcpTlsTransport({
    required this.identity,
    this.port = kPreferredPort,
    this.connectTimeout = kDefaultConnectTimeout,
    this.requestPeerCertificate = false,
    this.trustedPeerCertificatePems = const <String>[],
  });

  /// Supplies per-session certificate material. Must be cheap and must return
  /// *fresh* material every call - see [DeviceIdentity.beginSession].
  final DeviceIdentity identity;

  /// Port to try first; falls back to an ephemeral port when unavailable.
  final int port;

  /// Budget for [connect]; see [kDefaultConnectTimeout].
  final Duration connectTimeout;

  /// Whether to ask connecting clients for a certificate.
  ///
  /// ### Do not enable this without [trustedPeerCertificatePems]
  ///
  /// It makes dart:io request a client certificate, and BoringSSL then rejects
  /// the handshake when that certificate chains to nothing in our trust store -
  /// which is always, unless something is pinned there. Configuring
  /// [trustedPeerCertificatePems] implies this flag. Full analysis in
  /// [kCertFingerprintHeader].
  final bool requestPeerCertificate;

  /// Certificates (PEM) to trust when validating client certificates.
  ///
  /// ### What this is for
  ///
  /// [requestPeerCertificate] alone cannot work: asking for a client
  /// certificate that chains to an empty trust store makes BoringSSL reject the
  /// handshake outright. Give it something to verify *against* and the handshake
  /// completes and [TcpPeerLink.remoteCertFingerprint] becomes a verified fact on
  /// the serving side too.
  ///
  /// With self-signed per-session certificates the only honest source for this
  /// list is trust on first use: after a successful pairing, pin the peer's
  /// certificate here. That is a change the pairing layer owns (it is the thing
  /// that knows which peers are trusted), so until it plumbs this through, the
  /// default empty list means [kCertFingerprintHeader]'s fallback is in effect.
  /// The test suite exercises the verified path with a pinned certificate, so
  /// the capability is known to work rather than merely asserted.
  final List<String> trustedPeerCertificatePems;

  /// Whether the listener asks for a client certificate. Pinning anything implies
  /// asking, so a configured trust store cannot silently go unused.
  bool get _asksForClientCertificate =>
      requestPeerCertificate || trustedPeerCertificatePems.isNotEmpty;

  HttpServer? _server;
  SecureServerSocket? _listener;

  /// Client certificates observed at accept time, keyed by
  /// `remoteAddress:remotePort` because dart:io never exposes which socket a
  /// given [HttpRequest] arrived on.
  final Map<String, X509Certificate> _acceptedCerts = {};

  PeerApi? _api;
  SessionCredentials? _session;
  int? _boundPort;
  bool _closed = false;
  Future<void>? _closeFuture;
  /// Server-side links already established, keyed by the client's certificate
  /// fingerprint (the asserted one when TLS could not hand us the real
  /// certificate; see [kCertFingerprintHeader]).
  ///
  /// One logical [PeerLink] can span several TCP connections: dart:io pools
  /// sockets and a streaming `PUT` may open a second one. The serving side has
  /// no socket-stable handle for that, so it correlates requests by the
  /// fingerprint every client sends in [kCertFingerprintHeader] and hands the
  /// *same* [TcpPeerLink] to [PeerApi.handle] for the whole session. Without
  /// this, per-link state (`AeroPeerApi` pairs once, then a later request
  /// arrives on a fresh link object) would be lost between requests. The map is
  /// bounded for the same reason `_acceptedCerts` is.
  final Map<String, TcpPeerLink> _inboundLinks = {};
  final Set<TcpPeerLink> _links = {};

  @override
  String get name => 'tcp-tls';

  /// The port actually bound by [serve], or `null` when not serving.
  ///
  /// Never lies: if [kPreferredPort] was taken this is the ephemeral port the
  /// OS handed out, and that - not the preference - is what discovery must put
  /// in the mDNS TXT record.
  @override
  int? get boundPort => _boundPort;

  /// Fingerprints of the material from the most recent
  /// [DeviceIdentity.beginSession], i.e. what this transport would present or
  /// has presented.
  ///
  /// Not stable across [serve]/[connect] calls, on purpose: a fresh certificate
  /// per session is what makes a recorded fingerprint worthless later. Durable
  /// trust belongs in [PairingAuthority], keyed by [DeviceIdentity.deviceId]
  /// and its public key.
  @override
  List<String> get certFingerprints =>
      [if (_session case final s?) s.fingerprintHex];

  /// Fingerprint of the certificate we last presented, for diagnostics and for
  /// the pairing layer's display.
  String? get localCertFingerprint => _session?.fingerprintHex;

  // -------------------------------------------------------------------------
  // Serving
  // -------------------------------------------------------------------------

  /// Start listening and dispatch inbound requests to [api].
  ///
  /// Completes once bound, so [boundPort] is immediately safe to advertise.
  @override
  Future<void> serve(PeerApi api) async {
    if (_closed) {
      throw StateError('TcpTlsTransport.serve() called after close()');
    }
    if (_server != null) {
      throw StateError('TcpTlsTransport.serve() called twice');
    }
    _api = api;
    _session = await identity.beginSession();
    final context = _securityContextFor(_session!);

    _boundPort = await _bind(context);
    final server = _server!;
    server.idleTimeout = kIdleTimeout;
    server.listen(
      (HttpRequest request) => unawaited(_handleRequest(request)),
      onError: (Object error, StackTrace stack) {
        // A failed TLS handshake surfaces here once per connection and is not
        // fatal to the listener.
        log.fine('server stream error: $error');
      },
    );
    log.info('serving on $_boundPort fp=${_short(_session!.fingerprintHex)}');
  }

  /// Bind the listener, preferring [port] and falling back to an ephemeral port.
  ///
  /// Uses [SecureServerSocket.bind] + [HttpServer.listenOn] rather than
  /// [HttpServer.bindSecure] so the accepted `SecureSocket` is reachable - that
  /// is how send/receive buffer sizes get set, and the only way to read a client
  /// certificate (see [_ObservedServerSocket]). `_HttpServer.listen` already
  /// sets `TCP_NODELAY` on every accepted socket; we set it again anyway because
  /// it is free and it is the single most important socket knob in this app.
  ///
  /// If that path fails we degrade to [HttpServer.bindSecure]: no server-side
  /// buffer tuning and no peer certificate, but a working listener. Losing bulk
  /// throughput is strictly better than refusing to serve at all.
  Future<int> _bind(SecurityContext context) async {
    SecureServerSocket listener;
    try {
      listener = await _bindAt(context, port);
    } on SocketException catch (error) {
      // Nearly always EADDRINUSE, but any bind failure is handled identically:
      // take what the OS offers and advertise that instead of lying.
      //
      // Note `SocketException` is *not* an `OSError` in dart:io - the two
      // hierarchies are unrelated (`IOException` vs `OSError`), so catching
      // `OSError` here silently lets the preferred-port collision escape.
      log.warning('bind(:$port) failed ($error), using an ephemeral port');
      listener = await _bindEphemeral(context);
    } on OSError catch (error) {
      log.warning('bind(:$port) failed ($error), using an ephemeral port');
      listener = await _bindEphemeral(context);
    }

    _listener = listener;
    try {
      // `listenOn` does not take ownership of the ServerSocket, so close()
      // releases both halves.
      _server = HttpServer.listenOn(
        _ObservedServerSocket(listener, _onAcceptedSocket),
      );
    } catch (error) {
      await listener.close();
      _listener = null;
      log.warning('HttpServer.listenOn failed ($error); '
          'falling back to bindSecure without socket tuning');
      try {
        _server = await HttpServer.bindSecure(
          InternetAddress.anyIPv4,
          listener.port,
          context,
          requestClientCertificate: _asksForClientCertificate,
          shared: true,
        );
      } on SocketException catch (bindError) {
        throw AeroException('cannot listen for TLS', cause: bindError);
      } on OSError catch (bindError) {
        throw AeroException('cannot listen for TLS', cause: bindError);
      }
    }
    return listener.port;
  }

  Future<SecureServerSocket> _bindAt(SecurityContext context, int port) =>
      SecureServerSocket.bind(
        InternetAddress.anyIPv4,
        port,
        context,
        requestClientCertificate: _asksForClientCertificate,
        // Let other isolates bind the same port and share the incoming
        // connections rather than fighting over the preferred port.
        shared: true,
      );

  /// Bind on an OS-assigned port, translating a total failure into
  /// [AeroException]: nothing the peer could do about it, so discovery and the
  /// UI should report it as a local problem rather than a protocol error.
  Future<SecureServerSocket> _bindEphemeral(SecurityContext context) async {
    try {
      return await _bindAt(context, 0);
    } on SocketException catch (error) {
      throw AeroException('cannot listen for TLS on any port', cause: error);
    } on OSError catch (error) {
      throw AeroException('cannot listen for TLS on any port', cause: error);
    }
  }

  /// First sight of each accepted connection, before the HTTP layer touches it.
  void _onAcceptedSocket(SecureSocket socket) {
    tuneSocket(socket, role: 'server');
    final cert = socket.peerCertificate;
    if (cert == null) return;
    // Bounded: a long-lived process sees endless short connections and only
    // reclaims entries for one-shot connections, so cap the map rather than let
    // it track every socket this device has ever accepted.
    if (_acceptedCerts.length >= 128) _acceptedCerts.clear();
    _acceptedCerts[_socketKey(socket)] = cert;
  }

  static String _socketKey(Socket socket) =>
      '${socket.remoteAddress.address}:${socket.remotePort}';

  /// Serve one inbound request.
  Future<void> _handleRequest(HttpRequest req) async {
    final api = _api;
    final res = req.response;
    if (api == null) {
      // Only reachable if the listener outlived its PeerApi, i.e. a bug.
      res.statusCode = HttpStatus.serviceUnavailable;
      unawaited(res.close());
      return;
    }

    final peerCert = _acceptedCerts[_endpointKey(req)];
    // Authoritative when TLS actually handed us the peer's certificate.
    final verified =
        peerCert == null ? null : await certFingerprintHex(peerCert);

    final asserted = _assertedFingerprint(req);
    // Prefer the fingerprint TLS actually proved; fall back to the client's own
    // claim, exactly as [TcpPeerLink.remoteCertFingerprint] does. With neither,
    // the socket endpoint is the last resort so the link is not shared blindly.
    final peerKey = verified != null
        ? 'verified:$verified'
        : (asserted != null ? 'asserted:$asserted' : 'socket:${_endpointKey(req)}');

    if (_inboundLinks.length >= 128) _inboundLinks.clear();
    final link = _inboundLinks.putIfAbsent(
      peerKey,
      () => TcpPeerLink.server(
        api: api,
        localCertFingerprint: _session?.fingerprintHex ?? '',
        onClosed: _forgetInboundLink,
        remoteCertFingerprint: verified ?? asserted,
        remoteCertFingerprintIsVerified: verified != null,
      ),
    );
    _links.add(link);

    // The peer tells us who it is on every request via `X-Aero-Device*`
    // headers, because an inbound link has no outbound `GET /v1/info` of its
    // own. This is what makes the pairing code computable on the receiving
    // side: without a nonce the receiver derives the SAS from a null nonce and
    // every code mismatch is guaranteed.
    //
    // The headers are self-asserted, so they are only used for the *nonce* and
    // for display. Authentication still comes from the certificate
    // fingerprint, which TLS proved, and the SAS is compared by the human on
    // both screens.
    final assertedInfo = _assertedPeerInfo(req);
    if (assertedInfo != null) {
      link.remote = assertedInfo;
    }

    ApiResponse result;
    try {
      result = await api.handle(
        link,
        ApiRequest(
          method: req.method.toUpperCase(),
          path: req.uri.path,
          headers: _flatHeaders(req),
          // The live request stream. Handlers must consume it (or let dart:io
          // drain it) rather than collecting it, or memory goes O(file size).
          body: req,
          connection: link,
        ),
      );
    } on PeerException catch (error) {
      // The protocol vocabulary, not a crash: `ApiError.*` codes round-trip to
      // the caller's `PeerException.code` with the right HTTP status.
      result = ApiResponse.error(error.code, error.message);
    } catch (error, stack) {
      log.severe(
        'handler failed for ${req.method} ${req.uri.path}',
        error,
        stack,
      );
      result = ApiResponse.error(ApiError.internal, 'internal error');
    }

    try {
      await writeApiResponse(res, result);
    } catch (error) {
      log.fine('could not write response for ${req.uri.path}: $error');
    }

    if (!req.persistentConnection) {
      // dart:io has no connection-closed event for HTTP, so a non-persistent
      // connection finishing is the closest thing we get to "peer went away".
      _acceptedCerts.remove(_endpointKey(req));
      await link.markDisconnected();
    }
  }

  /// `remoteAddress:remotePort` for the socket [req] arrived on.
  ///
  /// dart:io never exposes that socket directly, and correlating an accepted
  /// connection (where TLS told us the peer's certificate) with the request now
  /// being served is the only way to attribute a certificate to a link. A TCP
  /// endpoint is unique per live connection, so this key is sound; the one
  /// theoretical hole is the OS handing the same ephemeral port to a new
  /// connection before the map entry is dropped, which can only mis-attribute a
  /// certificate that was pinned by the peer anyway.
  String _endpointKey(HttpRequest req) {
    final info = req.connectionInfo;
    if (info == null) return '<no-connection-info>';
    return '${info.remoteAddress.address}:${info.remotePort}';
  }

  /// Drop a closed inbound link from both registries.
  ///
  /// Wired as [TcpPeerLink.onClosed] so a link that reports the peer gone
  /// (see [TcpPeerLink.markDisconnected]) is not handed to a later request.
  void _forgetInboundLink(TcpPeerLink link) {
    _links.remove(link);
    _inboundLinks.removeWhere((_, TcpPeerLink value) => identical(value, link));
  }

  /// Flatten [HttpHeaders] into the single-valued map [ApiRequest.headers]
  /// wants, lower-casing names to match [ApiRequest.header].
  static Map<String, String> _flatHeaders(HttpRequest req) {
    final out = <String, String>{};
    req.headers.forEach((String name, List<String> values) {
      out[name.toLowerCase()] = values.join(', ');
    });
    return out;
  }

  /// The fingerprint the client asserted, if it is well-formed.
  ///
  /// Exactly 64 lowercase hex characters, nothing else: this value is hashed
  /// into the SAS, and accepting arbitrary length or arbitrary bytes here would
  /// be feeding unbounded, attacker-chosen input straight into the pairing
  /// layer.
  static String? _assertedFingerprint(HttpRequest req) {
    final raw = req.headers.value(kCertFingerprintHeader);
    if (raw == null) return null;
    final value = raw.trim().toLowerCase();
    if (value.length != 64) return null;
    for (final unit in value.codeUnits) {
      final hex = (unit >= 0x30 && unit <= 0x39) || (unit >= 0x61 && unit <= 0x66);
      if (!hex) return null;
    }
    return value;
  }

  /// Rebuild the caller's [PeerInfo] from its self-asserted headers.
  ///
  /// Deliberately strict about the nonce: a missing or empty nonce means the
  /// pairing code cannot be derived, and returning a `PeerInfo` with an empty
  /// nonce would produce a *code that is guaranteed not to match* rather than a
  /// clear failure. Returning null instead lets the API report a proper error.
  static PeerInfo? _assertedPeerInfo(HttpRequest req) {
    final deviceId = (req.headers.value(Header.deviceId) ?? '').trim();
    final nonce = (req.headers.value(kDeviceNonceHeader) ?? '').trim();
    if (deviceId.isEmpty || nonce.isEmpty) return null;

    // Cap everything: these strings come from the network and end up in the UI.
    String clip(String? v, int max) {
      final s = (v ?? '').trim();
      if (s.isEmpty) return '';
      return s.length <= max ? s : s.substring(0, max);
    }

    return PeerInfo(
      deviceId: clip(deviceId, 64),
      deviceName: clip(req.headers.value(kDeviceNameHeader), 80),
      os: aeroOsFromName(clip(req.headers.value(kDeviceOsHeader), 16)),
      osVersion: '',
      appVersion: '',
      publicKey: clip(req.headers.value(kDevicePublicKeyHeader), 128),
      protocolVersion: kProtocolVersion,
      capabilities: const {},
      nonce: clip(nonce, 64),
    );
  }

  // -------------------------------------------------------------------------
  // Dialing
  // -------------------------------------------------------------------------

  /// Dial [target] and perform the `GET /v1/info` handshake.
  ///
  /// The returned link is ready to use: [PeerLink.remote] is populated and
  /// [PeerLink.remoteCertFingerprint] holds the SHA-256 of the certificate the
  /// peer really presented, read from TLS rather than from any header.
  @override
  Future<PeerLink> connect(PeerAddress target) async {
    if (_closed) {
      throw PeerException(ApiError.internal, 'transport closed');
    }
    _session = await identity.beginSession();
    final context = _securityContextFor(_session!);
    final link = TcpPeerLink.client(
      host: target.host,
      port: target.port,
      context: context,
      localCertFingerprint: _session!.fingerprintHex,
      connectTimeout: connectTimeout,
      onClosed: _links.remove,
    );
    _links.add(link);

    try {
      // One budget for TCP connect, TLS handshake and /v1/info: a peer that
      // accepts the socket and then says nothing must never hang the UI.
      final info = await link.getJson(Api.info).timeout(
            connectTimeout,
            onTimeout: () =>
                throw PeerException(ApiError.internal, 'connect timeout'),
          );
      link.remote = PeerInfo.fromJson(info);
      await link.resolvePeerFingerprints();
      log.info('connected to $target '
          'fp=${_short(link.localCertFingerprint)} '
          'remoteFp=${_short(link.remoteCertFingerprint)}');
      return link;
    } on PeerException {
      await link.close();
      rethrow;
    } on Object catch (error) {
      await link.close();
      throw PeerException(
        ApiError.internal,
        _looksLikeTimeout(error) ? 'connect timeout' : 'connect failed: $error',
        error,
      );
    }
  }

  static bool _looksLikeTimeout(Object error) =>
      error is TimeoutException ||
      (error is SocketException &&
          error.message.toLowerCase().contains('timed out'));

  // -------------------------------------------------------------------------
  // Teardown
  // -------------------------------------------------------------------------

  /// Stop serving, close every link, release the socket. Idempotent.
  @override
  Future<void> close() => _closeFuture ??= _close();

  Future<void> _close() async {
    _closed = true;
    final links = _links.toList();
    _links.clear();
    _inboundLinks.clear();
    for (final link in links) {
      // Closing a link notifies the PeerApi, so pairing state cannot outlive
      // the socket it was attached to.
      await link.close();
    }
    _acceptedCerts.clear();

    // No shared HttpClient to release: every link owns its own, and closing the
    // links above already closed those.
    final server = _server;
    final listener = _listener;
    _server = null;
    _listener = null;
    try {
      await server?.close(force: true);
    } catch (error) {
      log.fine('HttpServer close failed: $error');
    }
    try {
      // listenOn() leaves ownership of the ServerSocket with us.
      await listener?.close();
    } catch (error) {
      log.fine('SecureServerSocket close failed: $error');
    }
    _boundPort = null;
    _api = null;
  }

  /// Build the TLS context for a session, plus whatever peer certificates the
  /// caller has pinned.
  ///
  /// `withTrustedRoots: false` matters twice: it skips loading the platform
  /// trust store (slower, and useless for self-signed certificates), and it
  /// keeps the context symmetric between its client and server uses. Peer
  /// certificates are then added explicitly, so the only trust in the system is
  /// trust somebody decided on.
  ///
  /// Note the `*Bytes` variants - they take raw PEM *bytes*. Their non-`_Bytes`
  /// siblings take file *paths*, and the old `useCertificate()` is gone: a wrong
  /// choice here yields a context with no identity at all, which fails much
  /// later and far more confusingly.
  SecurityContext _securityContextFor(SessionCredentials credentials) {
    if (credentials.signatureAlgorithm.contains('ed25519')) {
      // dart:io's BoringSSL client does not advertise `ed25519` in
      // `signature_algorithms`, so no Dart peer can complete a handshake with
      // this certificate: the failure surfaces as a bare "Connection terminated
      // during handshake", with no hint about the cause. Say it here, where it
      // can still be acted on. Session certificates must be ECDSA P-256 or RSA;
      // Ed25519 stays the *device identity* algorithm, which never touches TLS.
      log.warning('session certificate is ${credentials.signatureAlgorithm}; '
          'Dart TLS clients cannot negotiate it. Use ECDSA P-256.');
    }
    final context = SecurityContext(withTrustedRoots: false);
    context.useCertificateChainBytes(utf8.encode(credentials.certificatePem));
    context.usePrivateKeyBytes(utf8.encode(credentials.privateKeyPem));
    if (trustedPeerCertificatePems.isNotEmpty) {
      // This is what a requested client certificate is verified against; pinning
      // implies asking (_asksForClientCertificate), so this cannot go unused.
      context.setTrustedCertificatesBytes(
        utf8.encode(trustedPeerCertificatePems.join('\n')),
      );
    }
    return context;
  }

  static String _short(String? fingerprint) =>
      fingerprint == null ? 'none' : _shortFp(fingerprint);
}

/// Write an [ApiResponse] into [res] and close it.
///
/// Exactly one body shape is legal per response ([ApiResponse] guarantees it),
/// so this is a two-way branch rather than a negotiation. Setting
/// `contentLength` explicitly matters for the file endpoints: without it
/// dart:io uses chunked transfer encoding, and some middleboxes are unhappy
/// with chunked bodies they cannot buffer.
Future<void> writeApiResponse(HttpResponse res, ApiResponse r) async {
  final json = r.json;
  final body = r.body;
  res.statusCode = r.statusCode;
  if (json != null) {
    final encoded = utf8.encode(jsonEncode(json));
    res.headers
      ..contentType = ContentType.json
      ..contentLength = encoded.length;
    res.add(encoded);
  } else if (body != null) {
    res.headers
      ..contentType = ContentType.binary
      ..contentLength = body.length;
    res.add(body);
  } else {
    // Body-less answer (a successful cancel, say): state it rather than leaving
    // dart:io to invent a chunked encoding for zero bytes.
    res.headers.contentLength = 0;
  }
  await res.close();
}

// ---------------------------------------------------------------------------
// Socket tuning
// ---------------------------------------------------------------------------

/// `TCP_NODELAY`. Identically 1 on Linux, macOS, iOS and Windows.
///
/// The value people copy from BSD sources (`0x1001`) is **wrong on Darwin**:
/// macOS's `netinet/tcp.h` defines `TCP_NODELAY 0x01` and `0x10` is
/// `TCP_KEEPALIVE`, so "fixing" this to 0x1001 yields `ENOPROTOOPT` - or, at
/// 0x10, silently switches on keepalive probes.
const int _kTcpNoDelay = 1;

/// `SO_SNDBUF`: 0x1001 on macOS/iOS/Windows, 7 on Linux (classic
/// `sys/socket.h` numbering, which is also what SOL_SOCKET + 7 means).
const int _kSndBufPosix = 0x1001;
const int _kSndBufLinux = 7;

/// `SO_RCVBUF`: 0x1002 on macOS/iOS/Windows, 8 on Linux.
const int _kRcvBufPosix = 0x1002;
const int _kRcvBufLinux = 8;

/// Apply this transport's socket options, ignoring any failure.
///
/// ### Why each one
///
/// * `TCP_NODELAY` - Dart leaves Nagle's algorithm *on* for raw sockets, so each
///   small write can sit waiting for a coalesced segment. Bulk transfer barely
///   notices (a 4 MiB chunk always fills the window) but the control traffic
///   around a transfer - progress pings, status polls, the SAS exchange - pays
///   tens of milliseconds per round trip. dart:io's server already sets this on
///   accepted sockets (`_HttpServer.listen`); the client offers no such
///   courtesy, which is why [_TuneOnConnect] exists.
/// * `SO_SNDBUF`/`SO_RCVBUF` - 4 MiB each ([Transfer.sendBufferSize]). Defaults
///   are tiny (macOS: ~150 KB), which caps a single stream at roughly
///   150 KB/RTT: on Wi-Fi with a 30 ms RTT that is 5 MB/s rather than the
///   100 MB/s the link can carry. Widening the window is what makes "fast"
///   actually fast.
///
/// ### Failure policy
///
/// Every option is best-effort and each is isolated. A kernel that refuses one
/// of them - a hardened Android ROM, a sandbox, `ENOPROTOOPT` from an id that
/// does not exist on this platform - must never cost a working connection, so we
/// log at `fine` and carry on.
void tuneSocket(Socket socket, {required String role}) {
  if (Platform.isLinux) {
    _setInt(socket, RawSocketOption.levelTcp, _kTcpNoDelay, 1, 'TCP_NODELAY', role);
    _setInt(socket, RawSocketOption.levelSocket, _kSndBufLinux, Transfer.sendBufferSize, 'SO_SNDBUF', role);
    _setInt(socket, RawSocketOption.levelSocket, _kRcvBufLinux, Transfer.sendBufferSize, 'SO_RCVBUF', role);
  } else if (Platform.isMacOS || Platform.isIOS || Platform.isWindows) {
    _setInt(socket, RawSocketOption.levelTcp, _kTcpNoDelay, 1, 'TCP_NODELAY', role);
    _setInt(socket, RawSocketOption.levelSocket, _kSndBufPosix, Transfer.sendBufferSize, 'SO_SNDBUF', role);
    _setInt(socket, RawSocketOption.levelSocket, _kRcvBufPosix, Transfer.sendBufferSize, 'SO_RCVBUF', role);
  } else {
    log.fine('$role: socket tuning skipped on ${Platform.operatingSystem}');
  }
}

void _setInt(
  Socket socket,
  int level,
  int option,
  int value,
  String name,
  String role,
) {
  try {
    socket.setRawOption(RawSocketOption.fromInt(level, option, value));
  } catch (error) {
    log.fine('$role: could not set $name: $error');
  }
}

/// A [ServerSocket] that shows every accepted socket to a callback before
/// passing it on.
///
/// This is the entire trick that makes server-side tuning and peer-certificate
/// reading possible. Dart 3.13 has **no** `HttpServer.perConnection` hook and no
/// `HttpConnection` type - that API does not exist yet - and the only
/// documented way to reach the socket behind an [HttpRequest] is
/// [HttpResponse.detachSocket], which discards HTTP framing and would oblige us
/// to hand-write a parser. Not worth it for two socket options.
///
/// So we bind a [SecureServerSocket] ourselves (it is a `Stream<SecureSocket>`),
/// wrap it in this delegating [ServerSocket], and give the wrapper to
/// [HttpServer.listenOn]. The HTTP layer then sees sockets whose reads and
/// writes are already encrypted and decrypted - exactly what it expects - while
/// we get first refusal on every connection.
///
/// The price is ownership: `listenOn` does not close the ServerSocket, so
/// [TcpTlsTransport.close] releases both.
class _ObservedServerSocket extends Stream<Socket> implements ServerSocket {
  _ObservedServerSocket(this._inner, this._onAccepted);

  final SecureServerSocket _inner;
  final void Function(SecureSocket socket) _onAccepted;

  @override
  InternetAddress get address => _inner.address;

  @override
  int get port => _inner.port;

  @override
  Future<ServerSocket> close() => _inner.close().then((_) => this);

  @override
  StreamSubscription<Socket> listen(
    void Function(Socket event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _inner.listen(
        (SecureSocket socket) {
          try {
            _onAccepted(socket);
          } catch (error, stack) {
            // Diagnostics must never kill an accepted connection.
            log.fine('accepted-socket hook failed: $error', stack);
          }
          onData?.call(socket);
        },
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );
}

// ---------------------------------------------------------------------------
// Certificate fingerprints
// ---------------------------------------------------------------------------

/// Memo for [certFingerprintHex], keyed by PEM.
///
/// Fingerprints are computed from TLS callbacks and per-connection handlers,
/// so a long-running process would otherwise re-hash the same certificate once
/// per request. Bounded because certificates are bounded in number only by
/// however many sessions the peer runs.
final Map<String, String> _fingerprintCache = <String, String>{};

/// Lowercase hex SHA-256 over a certificate's DER bytes.
///
/// [X509Certificate.der] rather than [X509Certificate.sha1]: SHA-1 is the
/// fingerprint everyone prints, but the SAS is specified over SHA-256
/// ([Crypto.hash], and `SessionCredentials.fingerprintHex` says "SHA-256 of the
/// DER certificate"), and hashing the DER needs no PEM parsing, which is
/// ambiguous for multi-certificate chains.
Future<String> certFingerprintHex(X509Certificate certificate) async {
  final cached = _fingerprintCache[certificate.pem];
  if (cached != null) return cached;
  final digest = await Sha256().hash(certificate.der);
  final hex = digest.bytes
      .map((int byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
  if (_fingerprintCache.length >= 256) _fingerprintCache.clear();
  return _fingerprintCache[certificate.pem] = hex;
}

String _shortFp(String fingerprint) =>
    fingerprint.length <= 8 ? fingerprint : fingerprint.substring(0, 8);

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/// One peer, over TLS.
///
/// A link is an [HttpClient] plus, on the serving side, the [PeerApi] that owns
/// it. dart:io pools TCP connections underneath, so a link spans one *or more*
/// sockets; every socket in it negotiated with the same server certificate,
/// which is what makes a single [remoteCertFingerprint] meaningful. If that ever
/// stops holding - a proxy completing TLS twice, an attacker - the link logs a
/// warning and the SAS will not match anyway.
///
/// Construction is public so tests can drive a link against a hand-rolled
/// server; production code obtains links from [TcpTlsTransport.connect] or
/// [TcpTlsTransport.serve].
class TcpPeerLink implements PeerLink {
  /// Wrap an existing [client]. Used for inbound links and by tests.
  TcpPeerLink({
    required HttpClient client,
    required this.localCertFingerprint,
    required this.onClosed,
    String? remoteCertFingerprint,
    this.remoteCertFingerprintIsVerified = false,
    PeerApi? api,
  })  : // Public parameter names are worth more than the lint here: making these
        // private fields into initializing formals would force callers to write
        // `_client:` and `_remoteCertFingerprint:`.
        // ignore: prefer_initializing_formals
        _client = client,
        // ignore: prefer_initializing_formals
        _remoteCertFingerprint = remoteCertFingerprint,
        // ignore: prefer_initializing_formals
        _api = api;

  /// Build an outbound link and wire up the TLS policy.
  ///
  /// Synchronous on purpose: `HttpClient` construction cannot fail, the socket
  /// is dialled lazily on the first request, and [TcpTlsTransport.connect]
  /// enforces the end-to-end timeout.
  factory TcpPeerLink.client({
    required String host,
    required int port,
    required SecurityContext context,
    required String localCertFingerprint,
    required void Function(TcpPeerLink link) onClosed,
    Duration connectTimeout = kDefaultConnectTimeout,
    PeerApi? api,
  }) {
    final link = TcpPeerLink(
      client: HttpClient(context: context),
      localCertFingerprint: localCertFingerprint,
      onClosed: onClosed,
      api: api,
    );
    link
      .._targetHost = host
      .._targetPort = port
      .._configureOutbound(context: context, connectTimeout: connectTimeout);
    return link;
  }

  /// Build the link an inbound request arrived on.
  factory TcpPeerLink.server({
    required PeerApi api,
    required String localCertFingerprint,
    required void Function(TcpPeerLink link) onClosed,
    String? remoteCertFingerprint,
    bool remoteCertFingerprintIsVerified = false,
  }) =>
      TcpPeerLink(
        // Never used: an inbound link cannot dial back, because the peer's
        // listening port is not knowable from its ephemeral source port. Send
        // traffic with TcpTlsTransport.connect() instead.
        client: HttpClient(),
        api: api,
        localCertFingerprint: localCertFingerprint,
        remoteCertFingerprint: remoteCertFingerprint,
        remoteCertFingerprintIsVerified: remoteCertFingerprintIsVerified,
        onClosed: onClosed,
      );

  final HttpClient _client;
  final PeerApi? _api;

  /// Unregisters this link from its transport; called exactly once.
  final void Function(TcpPeerLink link) onClosed;

  @override
  final String localCertFingerprint;

  String? _remoteCertFingerprint;
  PeerInfo? _remote;
  bool _isPaired = false;
  bool _closed = false;
  bool _disconnectReported = false;
  Future<void>? _closeFuture;

  /// Requests whose bodies may still be moving; aborted by [close].
  final Set<HttpClientRequest> _inFlight = <HttpClientRequest>{};

  /// Certificates seen by TLS on this link, in order.
  final List<X509Certificate> _peerCertificates = <X509Certificate>[];

  String? _targetHost;
  int? _targetPort;

  @override
  String get transportName => 'tcp-tls';

  @override
  PeerInfo? get remote => _remote;

  /// Set by [TcpTlsTransport.connect] once `GET /v1/info` has been decoded.
  @override
  set remote(PeerInfo? value) => _remote = value;

  @override
  String? get remoteCertFingerprint => _remoteCertFingerprint;

  /// Whether [remoteCertFingerprint] came out of TLS.
  ///
  /// Not on the frozen [PeerLink] interface - the pairing layer should treat a
  /// `false` here on an inbound link as "this value is the peer's own claim,
  /// not a verified fact", and read the rationale in [kCertFingerprintHeader].
  /// Flipped to `true` by [resolvePeerFingerprints] once the fingerprint has
  /// been hashed out of a certificate the TLS stack actually showed us.
  bool remoteCertFingerprintIsVerified;

  @override
  bool get isPaired => _isPaired;

  /// Pairing state lives on the link and the pairing layer flips it once the six
  /// digits match on both screens.
  set isPaired(bool value) => _isPaired = value;

  /// True for a link created by [TcpTlsTransport.serve] rather than `connect`.
  bool get isInbound => _api != null;

  /// Record the certificate TLS handed us, warning if the peer changes its
  /// story between connections of the same link.
  ///
  /// Normally there is exactly one. Two distinct certificates mean something in
  /// the middle completed TLS twice with two identities - a proxy, or an
  /// attacker - which is exactly what the SAS exists to catch, so say so loudly
  /// instead of quietly trusting the first one.
  void _notePeerCertificate(X509Certificate certificate) {
    if (_peerCertificates.isEmpty) {
      _peerCertificates.add(certificate);
      return;
    }
    if (_peerCertificates
        .any((X509Certificate c) => c.pem == certificate.pem)) {
      return;
    }
    _peerCertificates.add(certificate);
    log.warning('peer presented a second, different TLS certificate on one '
        'link - possible interception; the pairing code must be confirmed');
  }

  /// Hash whatever certificates TLS has shown us so far.
  ///
  /// Called once by [TcpTlsTransport.connect] after the handshake, because
  /// SHA-256 is asynchronous (package:cryptography) while the TLS callbacks
  /// that see certificates are not. Anything observed later - a pooled
  /// connection opened after this call - is only reported, not folded in,
  /// because changing a fingerprint mid-session would invalidate the SAS that
  /// the user is staring at.
  Future<void> resolvePeerFingerprints() async {
    if (_peerCertificates.isEmpty || _remoteCertFingerprint != null) return;
    _remoteCertFingerprint =
        await certFingerprintHex(_peerCertificates.first);
    // It came out of the handshake, so it is a fact about the peer's key rather
    // than a claim about it.
    remoteCertFingerprintIsVerified = true;
  }

  /// Install the TLS policy on the outbound [HttpClient].
  ///
  /// Two settings here are load-bearing and easy to "clean up" by accident:
  /// [HttpClient.badCertificateCallback] and [HttpClient.connectionFactory].
  void _configureOutbound({
    required SecurityContext context,
    required Duration connectTimeout,
  }) {
    // Note: Dart 3.13's HttpClient takes its SecurityContext as a *constructor*
    // argument (`HttpClient(context: ...)`) - there is no `client.context`
    // setter, unlike some older snippets in the wild. The caller passes the
    // same [context] here, so we both present our ephemeral certificate (so the
    // peer can derive its half of the SAS) and accept the peer's.

    // ------------------------------------------------------------------------
    // badCertificateCallback -> true.  THIS LOOKS CATASTROPHIC. IT IS THE
    // DESIGN.  See the library docs and kCertFingerprintHeader.
    // ------------------------------------------------------------------------
    // Returning false, or deleting this, makes every peer unable to connect and
    // proves nothing: there is no CA anywhere in this protocol that could
    // validate a certificate minted a second ago. Authentication comes from the
    // six-digit SAS instead, and the fingerprint it hashes is read out of the
    // TLS handshake right here.
    _client.badCertificateCallback =
        (X509Certificate certificate, String host, int port) {
      _notePeerCertificate(certificate);
      return true;
    };

    // Never use a system proxy. This is a peer on the LAN, on a network that
    // usually has no infrastructure at all, and one corporate PAC file would
    // silently break every transfer while looking like a peer bug.
    _client.findProxy = (_) => 'DIRECT';

    // The only hook that exposes the outgoing socket: HttpClient gives no way to
    // set socket options on the TCP connection it opens by itself. We dial TLS
    // ourselves, tune the socket, and hand it back; the HTTP client then speaks
    // plain HTTP over that encrypted stream, which is exactly what
    // `ConnectionTask` exists for.
    _client.connectionFactory =
        (Uri uri, String? proxyHost, int? proxyPort) async {
      final task = await SecureSocket.startConnect(
        uri.host,
        uri.port,
        context: context,
        onBadCertificate: (X509Certificate certificate) {
          _notePeerCertificate(certificate);
          return true;
        },
      );
      return ConnectionTask.fromSocket<Socket>(
        task.socket
            .then((SecureSocket socket) {
              tuneSocket(socket, role: 'client');
              final certificate = socket.peerCertificate;
              if (certificate != null) _notePeerCertificate(certificate);
              return socket;
            })
            // startConnect() has no timeout parameter, so apply our own and make
            // sure the abandoned attempt actually releases its socket.
            .timeout(
              connectTimeout,
              onTimeout: () {
                task.cancel();
                throw SocketException(
                  'TLS handshake to ${uri.host}:${uri.port} timed out',
                  address: null,
                );
              },
            ),
        task.cancel,
      );
    };

    // See kIdleTimeout.
    _client.idleTimeout = kIdleTimeout;
  }

  @override
  Future<Map<String, dynamic>> requestJson(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  }) async {
    final request = await _open(method, path, headers);
    request.headers.contentType = ContentType.json;
    if (body != null) {
      final encoded = utf8.encode(jsonEncode(body));
      request.headers.contentLength = encoded.length;
      request.add(encoded);
    }
    return _sendAndDecode(request, path);
  }

  @override
  Future<Map<String, dynamic>> getJson(String path) =>
      requestJson('GET', path);

  /// Stream [data] to the peer at [path] as the request body.
  ///
  /// The body goes to [HttpClientRequest.addStream], and that is the entire
  /// point: dart:io pulls from the source only as fast as TLS drains, so a slow
  /// network throttles the disk read instead of filling RAM. Collecting the
  /// stream here - even into a temporary list - turns a 40 GiB file into an
  /// out-of-memory crash. Do not.
  ///
  /// [onProgress] is called with the cumulative byte count after each chunk and
  /// before it is handed to the socket, so a progress bar advances even while
  /// the socket is still backed up.
  @override
  Future<Map<String, dynamic>> putStream(
    String path,
    Stream<List<int>> data, {
    int? contentLength,
    Map<String, String>? headers,
    void Function(int bytesSent)? onProgress,
  }) async {
    final request = await _open('PUT', path, headers);
    request.headers.set(
      HttpHeaders.contentTypeHeader,
      ContentType.binary.mimeType,
    );
    if (contentLength != null) request.headers.contentLength = contentLength;

    var sent = 0;
    Stream<List<int>> counted() async* {
      await for (final chunk in data) {
        sent += chunk.length;
        onProgress?.call(sent);
        yield chunk;
      }
    }

    await request.addStream(counted());
    return _sendAndDecode(request, path);
  }

  /// Open a request against the peer, carrying our own fingerprint.
  Future<HttpClientRequest> _open(
    String method,
    String path,
    Map<String, String>? headers,
  ) async {
    final host = _targetHost;
    final port = _targetPort;
    if (host == null || port == null) {
      throw PeerException(
        ApiError.internal,
        'cannot send $method $path: an inbound link has no peer address '
        '(use TcpTlsTransport.connect to send)',
      );
    }
    final request = await _client.openUrl(
      method.toUpperCase(),
      Uri(scheme: 'https', host: host, port: port, path: path),
    );
    // Tell the peer who we are. Sent on every request, not just pairing: the
    // receiving side has no outbound request of its own (it has no connection
    // until we make one), so this is its only source of our nonce, and the
    // pairing code cannot be derived without it.
    final self = remote;
    if (self != null) {
      request.headers.set(Header.deviceId, self.deviceId);
      request.headers.set(kDeviceNameHeader, self.deviceName);
      request.headers.set(kDeviceNonceHeader, self.nonce);
      request.headers.set(kDevicePublicKeyHeader, self.publicKey);
      request.headers.set(kDeviceOsHeader, self.os.name);
    }

    if (headers != null) {
      headers.forEach(request.headers.set);
    }
    // Unless the caller overrode it, tell the peer our fingerprint: that is how
    // an inbound link learns who it is talking to. Ignored whenever a real
    // certificate is available (see kCertFingerprintHeader).
    if (headers == null || !headers.containsKey(kCertFingerprintHeader)) {
      request.headers.set(kCertFingerprintHeader, localCertFingerprint);
    }
    return request;
  }

  /// Send [request] and decode the reply, keeping the request tracked for
  /// [close] for as long as its body can still be moving.
  ///
  /// `HttpClientResponse` is a plain `Stream<List<int>>` in Dart 3.13 - there is
  /// no `done` future to hang a completion on - so "finished" means "the body
  /// has been drained", which is precisely what [_decodeJson] does.
  Future<Map<String, dynamic>> _sendAndDecode(
    HttpClientRequest request,
    String path,
  ) async {
    _inFlight.add(request);
    try {
      final response = await request.close();
      return await _decodeJson(response, path);
    } finally {
      _inFlight.remove(request);
    }
  }

  /// Decode a JSON response, turning non-2xx into a typed protocol error.
  ///
  /// Error bodies are `{"error": code, "message": ...}` by [ApiResponse.error],
  /// so callers branch on [PeerException.code] - one of [ApiError] - instead of
  /// matching English text. A missing or unparseable body degrades to
  /// [ApiError.internal]: a peer that cannot produce an error envelope is
  /// broken, not hostile, and inventing a protocol violation there would be a
  /// lie.
  Future<Map<String, dynamic>> _decodeJson(
    HttpClientResponse response,
    String path,
  ) async {
    final text = await response.transform(utf8.decoder).join();
    Map<String, dynamic>? decoded;
    if (text.isNotEmpty) {
      try {
        final value = jsonDecode(text);
        if (value is Map) decoded = value.cast<String, dynamic>();
      } catch (_) {
        decoded = null;
      }
    }
    if (response.statusCode >= 200 && response.statusCode < 300) {
      return decoded ?? const <String, dynamic>{};
    }
    final code = decoded?['error'];
    final message = decoded?['message'];
    throw PeerException(
      code is String && code.isNotEmpty ? code : ApiError.internal,
      message is String && message.isNotEmpty
          ? message
          : '${response.statusCode} from $path',
    );
  }

  /// Tell the [PeerApi] this peer went away. Idempotent.
  ///
  /// dart:io exposes no connection-closed event for HTTP - `HttpSession` is
  /// cookie-scoped, not connection-scoped, so it cannot stand in - so the
  /// signals that do exist drive this: a non-persistent connection finishing,
  /// a response failing mid-flight (the peer vanished), and [close]. Pairing
  /// state is per link, which means losing the socket must clear it; otherwise
  /// a link would keep claiming to be paired with nobody.
  Future<void> markDisconnected() async {
    if (_disconnectReported) return;
    _disconnectReported = true;
    try {
      _api?.onDisconnect(this);
    } catch (error, stack) {
      log.warning('PeerApi.onDisconnect threw', error, stack);
    }
  }

  /// Abort in-flight bodies and release the HTTP client. Idempotent.
  @override
  Future<void> close() => _closeFuture ??= _close();

  Future<void> _close() async {
    if (_closed) return;
    _closed = true;
    for (final request in _inFlight.toList()) {
      try {
        // abort() discards the unsent body without waiting for the peer, which
        // is what teardown wants, and the only way to stop a stalled upload.
        request.abort();
      } catch (error) {
        log.fine('abort failed: $error');
      }
    }
    _inFlight.clear();
    try {
      _client.close(force: true);
    } catch (error) {
      log.fine('HttpClient close failed: $error');
    }
    try {
      onClosed(this);
    } catch (error) {
      log.fine('link unregister failed: $error');
    }
    await markDisconnected();
  }
}