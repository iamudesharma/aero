/// Abstract contracts that every layer of Aero is written against.
///
/// The whole point of this file is that discovery, transport, crypto, and the
/// file store are *interfaces with multiple implementations*. A concrete
/// platform only ever supplies adapters; the protocol and session logic are
/// written once and are byte-identical everywhere.
///
/// Current implementations:
///   * discovery  -> `MdnsDiscovery` (bonsoir; all 5 native OSes)
///   * transport  -> `TcpTlsTransport`  (dart:io; all 6 targets)
///   * crypto     -> `Ed25519Identity` + `EphemeralCertAuthority`
///   * fileStore  -> `LocalFileStore`   (dart:io; all 6 targets)
library;

import 'dart:async';

import 'models.dart';

/// Raised when a peer violates the protocol, or when we cannot reach one.
/// Carries a machine-readable [code] so the UI can react (e.g. prompt for the
/// numeric code again) without string-matching messages.
class PeerException implements Exception {
  PeerException(this.code, [this.message = '', this.cause, this.details = const {}]);

  /// One of the constants on [ApiError].
  final String code;
  final String message;
  final Object? cause;

  /// Structured data the peer sent alongside the error.
  ///
  /// Needed because a non-2xx response body is otherwise discarded: a 409 that
  /// carries `resumeFrom: 1048576` is useless if the caller can only see the
  /// status code and must issue a follow-up request to recover the number.
  final Map<String, dynamic> details;

  /// HTTP status to use when this error originates on the serving side.
  int get httpStatus => switch (code) {
        ApiError.notPaired => 401,
        ApiError.sasMismatch || ApiError.sasExpired || ApiError.rejected => 403,
        ApiError.tooManyAttempts => 429,
        ApiError.noSpace => 507,
        ApiError.tooLarge => 413,
        ApiError.hashMismatch => 422,
        ApiError.conflict => 409,
        ApiError.cancelled => 499,
        ApiError.badRequest => 400,
        _ => 500,
      };

  @override
  String toString() =>
      'PeerException($code${message.isEmpty ? '' : ': $message'})';
}

/// Raised locally when discovery or connection is impossible (no LAN, port
/// unavailable, platform not supported). Distinct from [PeerException] because
/// no peer is at fault.
class AeroException implements Exception {
  AeroException(this.message, {this.cause});
  final String message;
  final Object? cause;
  @override
  String toString() => 'AeroException($message)';
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Finds peers and publishes our own presence.
///
/// Implementations must be resilient to hostile input: mDNS is unauthenticated,
/// so a peer record is untrusted data, never a fact.
abstract class DiscoveryService {
  /// Human-readable name of the backend, shown in diagnostics.
  String get backendName;

  /// Why discovery is unavailable right now, or `null` when it is working.
  /// Surfaced directly in the UI, because "no peers found" and "you have no
  /// local network access" look identical otherwise.
  String? get unavailableReason;

  /// Emits every peer seen, including repeats. The UI layer is responsible
  /// for deduplicating by [PeerInfo.deviceId] and expiring stale entries.
  Stream<DiscoveredPeer> get peers;

  /// Begin discovering others and advertising ourselves.
  ///
  /// [port] is the port our transport is actually listening on - it may differ
  /// from [kPreferredPort] and must be advertised truthfully.
  Future<void> start({required int port, required PeerInfo self});

  /// Stop advertising and discovering. Safe to call when never started.
  Future<void> stop();

  Future<void> dispose();
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// An inbound request from a peer, before it has been parsed.
class ApiRequest {
  const ApiRequest({
    required this.method,
    required this.path,
    required this.headers,
    required this.body,
    required this.connection,
  });

  /// Uppercase HTTP verb.
  final String method;

  /// Path with the query string stripped.
  final String path;

  final Map<String, String> headers;
  final Stream<List<int>> body;

  /// The transport connection, for handling `PUT`/blob uploads with
  /// backpressure instead of buffering.
  final PeerLink connection;

  String? header(String name) =>
      headers[name.toLowerCase()] ?? headers[name];

  int? get contentLength {
    final v = header('content-length');
    return v == null ? null : int.tryParse(v);
  }
}

/// What a handler returns. Exactly one of the two shapes is used.
class ApiResponse {
  /// A JSON body. `status` defaults to 200.
  ApiResponse.json(Map<String, dynamic> body, {int status = 200})
      : body = null,
        json = body,
        statusCode = status,
        mimeType = 'application/json';

  /// A raw byte body. Used for file downloads.
  ///
  /// [mimeType] is honoured by [writeApiResponse]; it defaults to
  /// `application/octet-stream`, which is correct for the binary transfer path.
  ApiResponse.bytes(List<int> data, {int status = 200, this.mimeType})
      : body = data,
        json = null,
        statusCode = status;

  /// An error, serialised as `{"error": code, "message": ...}`.
  factory ApiResponse.error(String code, [String message = '']) {
    final status = switch (code) {
      ApiError.notPaired => 401,
      ApiError.sasMismatch || ApiError.sasExpired || ApiError.rejected => 403,
      ApiError.tooManyAttempts => 429,
      ApiError.noSpace => 507,
      ApiError.tooLarge => 413,
      ApiError.hashMismatch => 422,
      ApiError.conflict => 409,
      ApiError.cancelled => 499,
      ApiError.badRequest => 400,
      _ => 500,
    };
    return ApiResponse.json(
      {'error': code, if (message.isNotEmpty) 'message': message},
      status: status,
    );
  }

  final List<int>? body;
  final Map<String, dynamic>? json;
  final int statusCode;

  /// Content type for [body]. Ignored when [json] is set.
  final String? mimeType;
}

/// Serves the `/v1` protocol on behalf of the app.
///
/// Keep this free of transport types: it receives an [ApiRequest] and returns
/// an [ApiResponse], so the same handler works whether bytes arrive over TLS,
/// a WebRTC data channel, or anything else we add later.
abstract class PeerApi {
  /// True once the peer on the other side of [link] has a confirmed pairing.
  /// The implementation tracks this per-connection.
  bool isPaired(PeerLink link);

  /// Handle one request. Throwing a [PeerException] produces the matching
  /// status code automatically.
  Future<ApiResponse> handle(PeerLink link, ApiRequest request);

  /// Called when a connection closes, so per-session state can be dropped.
  void onDisconnect(PeerLink link);
}

/// A live, authenticated connection to one peer.
abstract class PeerLink {
  /// Which transport produced this link, for diagnostics.
  String get transportName;

  /// Identity of the far side, as learned from `GET /v1/info` on connect.
  PeerInfo? get remote;

  /// Set by the transport immediately after the handshake populates [remote].
  ///
  /// Settable because dart:io has no connection-closed event for HTTP
  /// (`HttpSession` is cookie-scoped, not connection-scoped), so a link outlives
  /// individual requests and pairing state must be tracked per link rather than
  /// inferred from a socket event.
  set remote(PeerInfo? value);

  /// SHA-256 fingerprint of the far side's TLS certificate, hex. This is what
  /// the 6-digit pairing code is derived from, so it must come from the actual
  /// certificate and not from anything the peer asserts about itself.
  String? get remoteCertFingerprint;

  /// Local fingerprint, for computing the code symmetrically.
  String get localCertFingerprint;

  /// True once the user has confirmed matching codes on both sides.
  bool get isPaired;

  /// Send a JSON request and decode the JSON response.
  ///
  /// Throws [PeerException] with the server's `error` code on a non-2xx
  /// status, so callers can branch on [ApiError] values.
  Future<Map<String, dynamic>> requestJson(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  });

  /// `GET` a JSON document.
  Future<Map<String, dynamic>> getJson(String path);

  /// Stream [data] to the peer at [path] as a raw request body.
  ///
  /// Uses socket-level backpressure rather than buffering, so memory stays
  /// flat regardless of file size. [onProgress] reports cumulative bytes sent.
  Future<Map<String, dynamic>> putStream(
    String path,
    Stream<List<int>> data, {
    int? contentLength,
    Map<String, String>? headers,
    void Function(int bytesSent)? onProgress,
  });

  Future<void> close();
}

/// Carries bytes and JSON between peers.
///
/// The abstraction exists so a WebRTC data-channel implementation can be added
/// for the browser without touching protocol code. For `TcpTlsTransport` the
/// bytes underneath are TLS over TCP.
abstract class PeerTransport {
  String get name;

  /// The port actually bound. May differ from [kPreferredPort]; this is the
  /// value that must be advertised over mDNS.
  int? get boundPort;

  /// Certificate fingerprints for this transport's identity, hex. Length must
  /// be at least 1; more than one entry means the transport can present a
  /// different certificate per connection.
  List<String> get certFingerprints;

  /// Start serving. Returns once bound, so [boundPort] is valid.
  Future<void> serve(PeerApi api);

  /// Dial a peer. The returned link is usable immediately; [PeerLink.remote]
  /// is populated because the transport performs the `GET /v1/info` handshake.
  Future<PeerLink> connect(PeerAddress target);

  /// Stop serving and close all links.
  Future<void> close();
}

// ---------------------------------------------------------------------------
// Crypto / identity
// ---------------------------------------------------------------------------

/// This device's long-lived cryptographic identity.
///
/// Persisted across launches so trust-on-first-use can recognise a device the
/// user has paired with before. [deviceId] is the stable public handle;
/// [publicKey] proves it.
abstract class DeviceIdentity {
  /// Stable 128-bit identifier, hex. Not secret.
  String get deviceId;

  /// Base64 of the 32 raw Ed25519 public key bytes (not SPKI DER, which is 44
  /// bytes for Ed25519).
  String get publicKey;

  /// Per-launch nonce that must be fresh for every session.
  String freshNonce();

  /// Sign an arbitrary payload, proving possession of the private key.
  Future<String> sign(String payload);

  /// Verify a signature made by this device's key.
  Future<bool> verify(String payload, String signatureB64);

  /// Per-connection certificate material. Distinct from the device identity:
  /// these are throwaway and exist only to establish the TLS session.
  Future<SessionCredentials> beginSession();
}

/// Ephemeral per-session credentials.
///
/// The certificate exists for exactly one reason: to give the pairing code
/// something to hash. It is regenerated every session and never persisted —
/// pinning it would defeat the point.
class SessionCredentials {
  const SessionCredentials({
    required this.certificatePem,
    required this.privateKeyPem,
    required this.fingerprintHex,
    required this.publicKeyB64,
    this.signatureAlgorithm = 'ecdsa-p256',
  });

  /// Self-signed certificate, PEM. Consumed by
  /// `SecurityContext.useCertificateChainBytes`.
  final String certificatePem;
  final String privateKeyPem;

  /// SHA-256 of the DER certificate, lowercase hex.
  ///
  /// Computed over DER rather than PEM so both sides can hash exactly the bytes
  /// the other sent, and so an external tool can reproduce it.
  final String fingerprintHex;

  /// Base64 public key matching [privateKeyPem]. This is the *session* key, not
  /// the device identity key — the two are unrelated.
  final String publicKeyB64;

  /// Signature algorithm of [certificatePem]: `ecdsa-p256` or `ed25519`.
  ///
  /// **This field exists because Dart's TLS client cannot use Ed25519
  /// certificates.** Verified directly: a Dart TLS client negotiating against a
  /// Dart TLS server fails the handshake (`HandshakeException: Connection
  /// terminated during handshake`) when the certificate is Ed25519, and succeeds
  /// against ECDSA P-256 using otherwise identical code. Dart's bundled BoringSSL
  /// does not advertise `ed25519` in `signature_algorithms`, so a client has
  /// nothing to offer and no ciphersuite can complete. A BoringSSL *server* can
  /// still serve Ed25519 — it is specifically the client side that is limited.
  ///
  /// Consequence for the design: Ed25519 remains the device-identity algorithm
  /// (used directly via `package:cryptography`, with no TLS involvement), while
  /// the per-session transport certificate must be ECDSA P-256 or RSA.
  final String signatureAlgorithm;
}

/// Decides whether the two displayed codes match, and remembers devices the
/// user has already paired with (trust on first use).
abstract class PairingAuthority {
  /// Compute the code both sides will display.
  ///
  /// Deterministic in both [localFingerprint] and [remoteFingerprint], and
  /// order-independent (they are sorted before hashing) so neither side needs
  /// to agree on who initiates.
  PairingProof deriveProof({
    required String localFingerprint,
    required String remoteFingerprint,
    required String nonce,
    String method = 'sas',
  });

  /// True when the two codes match and the proof has not expired.
  bool verifyProof(PairingProof presented, PairingProof expected);

  /// Record a confirmed peer so future sessions can skip the code.
  Future<void> rememberPeer({required String deviceId, required String publicKey});

  /// Look up a previously paired peer.
  Future<TrustState> lookupTrust({required String deviceId, required String publicKey});

  /// Whether pairing attempts against [deviceId] are currently blocked.
  /// Implementations enforce [Pairing.maxAttempts] / [Pairing.attemptCooldown].
  bool isRateLimited(String deviceId);

  /// Record a failed attempt.
  void recordFailure(String deviceId);

  Future<void> forgetPeer(String deviceId);
}

// ---------------------------------------------------------------------------
// File storage
// ---------------------------------------------------------------------------

/// One file's progress through a transfer.
enum TransferState { queued, offered, accepted, transferring, verifying, done, failed, skipped, cancelled }

/// Live progress for one file, suitable for driving a progress bar.
class FileProgress {
  const FileProgress({
    required this.entry,
    required this.state,
    this.bytesTransferred = 0,
    this.error,
  });

  final FileEntry entry;
  final TransferState state;
  final int bytesTransferred;
  final String? error;

  /// 0.0 - 1.0. Returns 0 for a zero-byte file so the UI can show it as
  /// complete rather than dividing by zero.
  double get fraction =>
      entry.size <= 0 ? (state == TransferState.done ? 1 : 0) : (bytesTransferred / entry.size).clamp(0.0, 1.0);
}

/// Where files come from and go to. Abstracted so a browser build can use
/// the File System Access API instead of the filesystem.
abstract class FileStore {
  /// Free bytes available for new data, or `null` when unknown.
  Future<int?> freeSpace();

  /// Create a staging location for an inbound transfer and preallocate it.
  ///
  /// Preallocation matters: without it a large sequential write fragments
  /// APFS/NTFS/ext4 badly and throughput collapses. In dart:io this is done
  /// with `RandomAccessFile.truncateSync(size)` — there is no `setLengthSync`.
  ///
  /// Implementations must treat the returned path as private to this store and
  /// must reject peer-supplied path components outright rather than sanitising
  /// them into something plausible.
  Future<StagedFile> stage(FileEntry entry, String sessionId);

  /// Final destination for a completed file.
  Future<String> commit(StagedFile staged, String sessionId);

  /// Discard a partially received file.
  Future<void> discard(StagedFile staged);

  /// Bytes already stored for [entryId], or 0 if nothing. Used to resume.
  Future<int> existingBytes(String sessionId, String entryId);
}

/// A file being received.
class StagedFile {
  const StagedFile({
    required this.entryId,
    required this.path,
    required this.size,
    this.name,
    this.relPath,
    this.digest,
  });

  final String entryId;

  /// Where bytes are being written. Controlled entirely by the store: keyed by
  /// session and entry id only, so a peer-supplied name cannot influence it.
  final String path;

  final int size;

  /// The peer's display name, retained so [FileStore.commit] can name the file
  /// on disk without re-reading the offer.
  final String? name;

  /// Directory portion, relative to the transfer root, already validated.
  final String? relPath;

  /// SHA-256 computed over the received bytes, lowercase hex.
  final String? digest;
}

/// Bytes of a local file, in [Transfer.chunkSize] slices, ready to be streamed.
/// Produces file contents in fixed-size slices for streaming to a peer.
///
/// An interface rather than a top-level function so the browser build can swap
/// in a File System Access implementation and still satisfy the same contract.
abstract class ChunkedFileReader {
  /// Reads [path] from [fromOffset] in [Transfer.chunkSize] slices.
  ///
  /// Deliberately a `Stream` rather than a callback: the transport's
  /// `addStream`/`pipe` machinery provides real backpressure, so a slow network
  /// throttles disk reads instead of filling memory. Peak RSS stays at one
  /// chunk regardless of file size.
  Stream<List<int>> chunkedFileStream(String path, {int? fromOffset});
}