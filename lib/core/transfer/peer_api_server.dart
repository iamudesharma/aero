/// Receiving-side implementation of the `/v1` protocol.
///
/// This is the code a hostile peer spends most of its time attacking, so the
/// shape of the whole file is defensive:
///
///  * **Every endpoint but `GET /v1/info` and `POST /v1/pair` demands a paired
///    link**, checked once at the top of [handle] instead of being repeated in
///    eight handlers where one copy would eventually be forgotten.
///  * **JSON bodies are capped** at [maxJsonBodyBytes]. An `Offer` is
///    attacker-controlled length; without a cap a peer can make this process
///    allocate until it dies, and `Transfer.maxFilesPerTransfer` only bounds
///    *our* parse of the result, not the bytes we were asked to buffer.
///  * **File bytes are never buffered.** The `PUT` body is piped straight into
///    a preallocated `RandomAccessFile`, and SHA-256 is folded in as each slice
///    goes past. Peak memory during a 1 TiB transfer is one chunk, same as a
///    1 KiB one.
///  * **Integrity claims from the peer are treated as hints.** `/v1/complete`
///    re-reads every staged file and recomputes its digest. A sender that lies
///    about what it sent gets a failure, not a file.
///
/// ## Resume
///
/// The receiver is the source of truth for "how much have we got", because the
/// sender can always re-read its file but the receiver cannot recover bytes that
/// were never written. Two mechanisms make that answer survive a dropped
/// connection:
///
///  1. `PUT` honours `Content-Range: bytes=N-` and answers `409 {resumeFrom: N}`
///     when the requested offset does not match what is staged.
///  2. `GET /v1/file/{id}` reports the staged byte count on demand, so a sender
///     that lost track can re-synchronise without guessing.
///
/// The subtle part is that [FileStore.existingBytes] reads the *file length*,
/// and a staged file is preallocated to its full size — so an interrupted
/// transfer must shrink its `.part` back to the number of bytes that actually
/// landed. That happens in the `PUT`'s `finally` and again in [onDisconnect].
/// Without it every resume would claim "already complete" and silently transfer
/// nothing.

library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';
import 'local_file_store.dart';

/// Cap on any JSON request body. ~8 MiB comfortably fits the largest legal
/// manifest (`Transfer.maxFilesPerTransfer` entries of a few hundred bytes) with
/// room to spare, while staying small enough that a hostile peer cannot push us
/// into the OOM killer.
const int kMaxJsonBodyBytes = 8 * 1024 * 1024;

/// Serves `/v1` on behalf of the app. Transport-free by construction: it only
/// ever sees an [ApiRequest] and returns an [ApiResponse] or throws a
/// [PeerException], so the same code works over TLS, a data channel, or the
/// in-process [FakePeerLink] the tests use.
class AeroPeerApi implements PeerApi {
  AeroPeerApi({
    required this.selfInfo,
    required this.store,
    required this.authority,
    this.maxJsonBodyBytes = kMaxJsonBodyBytes,
    this.onOffer,
    this.onProgress,
    this.onComplete,
    this.onPairingChallenge,
  });

  /// Injected so the handler has no global singleton and tests can pretend to
  /// be any device.
  final PeerInfo Function() selfInfo;

  /// Asks the user whether to accept an inbound offer.
  ///
  /// Pairing already establishes *who* the peer is, but consent to write files
  /// to disk is a separate decision the user must still make. Returning false
  /// yields a clean per-file `notAccepted` rejection rather than a protocol
  /// error, so the sender sees a normal refusal.
  ///
  /// When null the offer is accepted, which keeps headless tests and the CLI
  /// path working without a UI.
  final Future<bool> Function(PeerLink link, Offer offer)? onOffer;

  /// Reports received-byte counts so the UI can render an inbound transfer.
  final void Function(PeerLink link, String fileId, int received, int total)? onProgress;

  /// Reports the receiver's final verdict for a session.
  final void Function(PeerLink link, CompletionResult result)? onComplete;

  /// Asks the *receiving* user to compare [expected] with the sender's screen.
  ///
  /// This is what makes the 6-digit code a mutual check instead of a one-sided
  /// one. The initiator already showed the code; without this the receiving
  /// user never sees a value to compare, and the pairing reduces to "trust
  /// whoever can reach me". Returning false rejects the pairing, and the
  /// rejection is reported to the sender as [ApiError.rejected].
  ///
  /// Called only after the presented code has already been verified to match
  /// [expected], so a mismatched code never reaches the users' screens — a
  /// mismatch is a protocol failure, not a question.
  final Future<bool> Function(PeerLink link, PairingProof expected)? onPairingChallenge;

  /// Where inbound bytes land. [FileStore] (not a concrete type) so the browser
  /// build can substitute an OPFS implementation.
  final FileStore store;

  /// Owns pairing decisions: SAS derivation, trust-on-first-use, rate limiting.
  final PairingAuthority authority;

  /// Cap on any JSON request body. See [kMaxJsonBodyBytes].
  final int maxJsonBodyBytes;

  /// Per-connection state, keyed by the [PeerLink]. Identity-keyed on purpose:
  /// two connections to the same peer are two independent sessions, and the
  /// transport layer is what decides to reuse a link.
  final Map<PeerLink, _LinkState> _links = {};

  /// Fire-and-forget cleanups (see [onDisconnect]). Exposed through [drain] so
  /// callers that care can wait for them.
  final List<Future<void>> _pending = [];

  /// SHA-256 is cheap enough to construct per digest; a single shared instance is
  /// not safe because `HashAlgorithm` is stateless but the *sinks* we create from
  /// it are not.
  final HashAlgorithm sha256 = Sha256();

  @override
  bool isPaired(PeerLink link) => _links[link]?.paired ?? false;

  @override
  Future<ApiResponse> handle(PeerLink link, ApiRequest request) async {
    final state = _stateFor(link);
    final method = request.method.toUpperCase();
    final path = request.path;

    // --- the one place authorisation happens -------------------------------
    // Anything not on the allow-list needs a confirmed pairing. Doing this at
    // the top rather than inside each handler means a new endpoint is
    // protected-by-default: forgetting to add the check is impossible because
    // there is nothing to forget.
    if (!_isPublic(method, path) && !state.paired) {
      coreLog.warning('rejecting $method $path from an unpaired peer');
      throw PeerException(ApiError.notPaired, 'pair before $path');
    }

    try {
      if (method == 'GET' && path == Api.info) {
        return _info();
      }
      if (method == 'POST' && path == Api.pair) {
        return await _pair(link, state, request);
      }
      if (method == 'POST' && path == Api.offer) {
        return await _offer(link, state, request);
      }
      if (method == 'PUT' && path.startsWith('${Api.file}/')) {
        return await _putFile(link, state, request);
      }
      if (method == 'GET' && path.startsWith('${Api.file}/')) {
        return await _fileStatus(state, request);
      }
      if (method == 'POST' && path == Api.complete) {
        return await _complete(link, state, request);
      }
      if (method == 'POST' && path == Api.cancel) {
        return await _cancel(state, request);
      }

      return ApiResponse.error(
        ApiError.badRequest,
        'no route for $method $path',
      );
    } on PeerException {
      // Protocol-level failures carry a machine-readable code; the transport
      // turns [PeerException.httpStatus] into the HTTP status.
      rethrow;
    } catch (e, s) {
      // A bug in this file must not take the listener down, and must not leak a
      // stack trace to the peer.
      coreLog.severe('unhandled error serving $method $path', e, s);
      return ApiResponse.error(ApiError.internal, 'internal error');
    }
  }

  @override
  void onDisconnect(PeerLink link) {
    final state = _links.remove(link);
    if (state == null) return;
    state.detached = true;

    // Deliberately NOT deleting the staged files — that is precisely what makes
    // resume work. The sender reconnects, re-offers with the same session id,
    // and `store.existingBytes` picks up where the `.part` left off.
    //
    // The one thing that *must* happen is making each `.part` honest about how
    // many bytes landed, because `existingBytes` reads the file length and a
    // preallocated file always reports its full size.
    _track(_shrinkInterrupted(state));
  }

  /// Awaits the asynchronous cleanup started by [onDisconnect]. Not part of the
  /// [PeerApi] contract; the transport never needs it, but tests and the app's
  /// shutdown path do.
  Future<void> drain() async {
    while (_pending.isNotEmpty) {
      final batch = List<Future<void>>.from(_pending);
      _pending.clear();
      await Future.wait(batch);
    }
  }

  /// Closes everything this handler owns. Safe to call more than once.
  Future<void> dispose() async {
    _links.clear();
    await drain();
  }

  // ---------------------------------------------------------------------------
  // Routing helpers
  // ---------------------------------------------------------------------------

  static bool _isPublic(String method, String path) =>
      (method == 'GET' && path == Api.info) ||
      (method == 'POST' && path == Api.pair);

  _LinkState _stateFor(PeerLink link) =>
      _links.putIfAbsent(link, _LinkState.new);

  void _track(Future<void> work) {
    _pending.add(work);
    unawaited(
      work.catchError((Object e, StackTrace s) {
        coreLog.warning('background cleanup failed', e, s);
      }),
    );
  }

  ApiResponse _info() {
    final info = selfInfo();
    return ApiResponse.json(<String, dynamic>{
      ...info.toJson(),
      'maxChunkSize': Transfer.chunkSize,
      'maxFileSize': Transfer.maxFileSize,
      'maxParallelFiles': Transfer.maxParallelFiles,
    });
  }

  // ---------------------------------------------------------------------------
  // POST /v1/pair
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _pair(
    PeerLink link,
    _LinkState state,
    ApiRequest request,
  ) async {
    final body = await _readJson(request);

    final claimed = body['deviceId']?.toString().trim() ?? '';
    // The device id is a rate-limiting key, so prefer what the transport
    // actually learned from the TLS handshake and only fall back to the body's
    // claim. An attacker supplying a fresh id per attempt must not get a fresh
    // budget, and [Header.deviceId] is at least bound to one connection.
    final deviceId = (link.remote?.deviceId.isNotEmpty ?? false)
        ? link.remote!.deviceId
        : (claimed.isNotEmpty ? claimed : 'unknown');
    final publicKey =
        body['publicKey']?.toString() ?? (link.remote?.publicKey ?? '');

    if (authority.isRateLimited(deviceId)) {
      coreLog.warning('pairing rate limited for $deviceId');
      throw PeerException(
        ApiError.tooManyAttempts,
        'too many pairing attempts',
      );
    }

    final nonce = body['nonce']?.toString() ?? link.remote?.nonce ?? '';

    // Trust on first use: a device whose key we have already pinned pairs
    // without asking the user again. An explicit `confirm` from a *new* device
    // still goes through the short code below.
    if (body['confirm'] != true) {
      final trust = await authority.lookupTrust(
        deviceId: deviceId,
        publicKey: publicKey,
      );
      if (trust == TrustState.known) {
        state.paired = true;
        coreLog.info('trust-on-first-use accepted for $deviceId');
        return ApiResponse.json(
          PairingResult(paired: true, trustState: trust).toJson(),
        );
      }
      throw PeerException(ApiError.notPaired, 'pairing confirmation required');
    }

    final presented = _proofFrom(body['proof']);
    final expected = authority.deriveProof(
      localFingerprint: link.localCertFingerprint,
      remoteFingerprint: link.remoteCertFingerprint ?? '',
      nonce: nonce,
      method: presented.method,
    );
    if (presented.isExpired() || !authority.verifyProof(presented, expected)) {
      authority.recordFailure(deviceId);
      coreLog.warning('pairing code mismatch with $deviceId');
      throw PeerException(ApiError.sasMismatch, 'pairing codes differ');
    }

    // The codes agree cryptographically. That is necessary but not sufficient:
    // the receiving user must still confirm the two screens show the same
    // digits, which is the only way to catch a relay that terminated both TLS
    // sessions itself.
    final challenge = onPairingChallenge;
    if (challenge != null) {
      final approved = await challenge(link, expected);
      if (!approved) {
        authority.recordFailure(deviceId);
        coreLog.info('pairing declined by the receiving user for $deviceId');
        throw PeerException(
          ApiError.rejected,
          'the receiving device declined the pairing',
        );
      }
    }

    await authority.rememberPeer(deviceId: deviceId, publicKey: publicKey);
    state.paired = true;
    coreLog.info('paired with $deviceId');
    return ApiResponse.json(
      const PairingResult(paired: true, trustState: TrustState.known).toJson(),
    );
  }

  /// Builds the presented proof from the wire.
  ///
  /// The wire carries only `{method, value}` — the freshness window is decided
  /// locally. Accepting a peer-supplied `expiresAt` would let a peer keep a
  /// recorded code alive indefinitely, defeating the nonce replay protection the
  /// code exists for.
  PairingProof _proofFrom(Object? raw) {
    final map = raw is Map<String, dynamic> ? raw : null;
    if (map == null) {
      throw PeerException(ApiError.badRequest, 'missing pairing proof');
    }
    final method = map['method']?.toString() ?? '';
    final value = map['value']?.toString() ?? '';
    if (method.isEmpty) {
      throw PeerException(ApiError.badRequest, 'pairing proof has no method');
    }
    if (value.length != Pairing.codeDigits || !_isDigits(value)) {
      throw PeerException(ApiError.badRequest, 'malformed pairing code');
    }
    return PairingProof(
      method: method,
      value: value,
      expiresAt: DateTime.now().add(Pairing.codeLifetime),
    );
  }

  static bool _isDigits(String s) {
    for (final unit in s.codeUnits) {
      if (unit < 0x30 || unit > 0x39) return false;
    }
    return true;
  }

  // ---------------------------------------------------------------------------
  // POST /v1/offer
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _offer(PeerLink link, _LinkState state, ApiRequest request) async {
    final offer = _parseOffer(await _readJson(request));

    // A cancel can arrive before its own offer does: the sender may abort while
    // this request is still queued or still uploading, and the responses then
    // interleave arbitrarily. Without this check the offer stages files *after*
    // the cancel has already swept, leaving a `.part` behind that nothing will
    // ever clean up — and which the next attempt would misread as a resumable
    // prefix.
    if (state.cancelled) {
      coreLog.info('offer for session ${offer.sessionId} ignored: already cancelled');
      return ApiResponse.json(
        OfferResponse(
          sessionId: offer.sessionId,
          accepted: const [],
          rejected: [
            for (final f in offer.files) (f.id, RejectReason.notAccepted),
          ],
          error: ApiError.cancelled,
        ).toJson(),
      );
    }

    state.beginSession(offer.sessionId, offer);
    coreLog.info(
      'offer: session ${offer.sessionId} with ${offer.files.length} files '
      '(${(offer.files.fold<int>(0, (a, f) => a + f.size)) ~/ 1024} KiB)',
    );

    // -----------------------------------------------------------------------
    // Structural validation happens BEFORE the user is asked.
    // -----------------------------------------------------------------------
    // The order matters for the user's trust: prompting someone to accept a
    // transfer and then refusing it on a rule we could have checked first makes
    // the app look broken. Every check below is cheap and needs no network and
    // no prompt, so all of them run before `onOffer`.
    if (offer.files.length > Transfer.maxFilesPerTransfer) {
      coreLog.warning('offer refused: ${offer.files.length} files exceeds the cap');
      return ApiResponse.json(
        OfferResponse(
          sessionId: offer.sessionId,
          accepted: const [],
          rejected: [
            for (final f in offer.files) (f.id, RejectReason.tooManyFiles),
          ],
          error: ApiError.tooLarge,
        ).toJson(),
      );
    }

    for (final entry in offer.files) {
      if (entry.size < 0) {
        throw PeerException(
          ApiError.badRequest,
          'negative size for ${entry.id}',
        );
      }
    }

    // Free-space pre-flight. `freeSpace()` returns null on every native
    // platform (no statvfs in dart:io), so this is a no-op there and the real
    // guard is `stage()` failing cleanly with ENOSPC — which happens *now*,
    // before the peer has spent a single byte of network on us.
    //
    // Counted only over files we will actually accept: if the manifest also
    // contains files we are going to reject as oversized, refusing the whole
    // offer for space they would never use would be wrong.
    final total = offer.files
        .where((f) => f.size <= Transfer.maxFileSize)
        .fold<int>(0, (a, f) => a + f.size);
    final free = await store.freeSpace();
    if (free != null) {
      final needed = (total * Transfer.requiredFreeSpaceFactor).ceil();
      if (free < needed) {
        coreLog.warning('offer refused: need $needed bytes, have $free');
        return ApiResponse.json(
          OfferResponse(
            sessionId: offer.sessionId,
            accepted: const [],
            rejected: [
              for (final f in offer.files) (f.id, RejectReason.noSpace),
            ],
            error: ApiError.noSpace,
          ).toJson(),
        );
      }
    }

    // Only now, with every structural reason to refuse already ruled out, is the
    // user asked. A prompt therefore always leads to either an accepted or a
    // user-declined offer, never to a surprise refusal.
    final approval = onOffer;
    if (approval != null) {
      final accepted = await approval(link, offer);
      if (!accepted) {
        coreLog.info('offer ${offer.sessionId} declined by the user');
        return ApiResponse.json(
          OfferResponse(
            sessionId: offer.sessionId,
            accepted: const [],
            rejected: [
              for (final f in offer.files) (f.id, RejectReason.notAccepted),
            ],
          ).toJson(),
        );
      }
    }

    final accepted = <String>[];
    final rejected = <(String, RejectReason)>[];
    final resume = <String, int>{};
    final seen = <String>{};

    for (final entry in offer.files) {
      // Re-checked per file, not just once at the top of `_offer`: the cancel
      // can arrive while this loop is awaiting `stage`, so a check that only
      // ran before the loop would still let the remaining files be staged.
      // `stage` preallocates, so a file staged after the cancel is a
      // multi-gigabyte `.part` that nothing will clean up until the next
      // session happens to reuse the id.
      if (state.cancelled) {
        coreLog.info('offer: cancelled while staging; stopping at ${entry.id}');
        rejected.add((entry.id, RejectReason.notAccepted));
        continue;
      }
      if (!seen.add(entry.id)) {
        rejected.add((entry.id, RejectReason.duplicate));
        continue;
      }
      if (entry.size > Transfer.maxFileSize) {
        rejected.add((entry.id, RejectReason.tooLarge));
        continue;
      }
      // Validate the peer's names *here* so a traversal attempt is a clean
      // per-file rejection the UI can explain, instead of an exception thrown
      // during commit after the whole transfer has run.
      try {
        LocalFileStore.sanitiseDisplayName(entry.name);
        LocalFileStore.sanitiseRelPath(entry.relPath);
      } on PeerException {
        rejected.add((entry.id, RejectReason.unsupportedName));
        continue;
      }

      // Stage *before* measuring. `stage` deliberately leaves an existing
      // `.part` alone so resume keeps its bytes, so measuring first and staging
      // second would report a length for a file that has not been re-opened yet.
      final StagedFile staged;
      try {
        staged = await store.stage(entry, offer.sessionId);
      } on PeerException {
        rethrow;
      } on FileSystemException catch (e) {
        coreLog.warning('stage failed for ${entry.id}: ${e.osError?.message}');
        rejected.add((entry.id, RejectReason.noSpace));
        continue;
      }
      // The cancel may have landed while `stage` was running, in which case this
// file is already on disk and must be cleaned up here rather than left for
// a session that will never come.
      if (state.cancelled) {
        coreLog.info('offer: cancelled during ${entry.id}; discarding it');
        await store.discard(staged).catchError((Object _) {});
        rejected.add((entry.id, RejectReason.notAccepted));
        continue;
      }
      state.staged[entry.id] = staged;
      state.entries[entry.id] = entry;

      final already = await _resumePoint(state, entry, staged.path);
      state.received[entry.id] = already;
      if (already > 0) resume[entry.id] = already;
      accepted.add(entry.id);
    }

    if (accepted.isEmpty && rejected.isNotEmpty) {
      coreLog.info('offer refused entirely: ${rejected.length} rejections');
    }
    return ApiResponse.json(
      OfferResponse(
        sessionId: offer.sessionId,
        accepted: accepted,
        rejected: rejected,
        resume: resume,
      ).toJson(),
    );
  }

  /// How many bytes of [entry] are already on disk.
  ///
  /// In-memory truth (this connection already tracked the write) always wins.
  ///
  /// Otherwise the staged file's length is used, with one deliberate
  /// exception: a `.part` whose length already equals the declared size is
  /// treated as *zero*. A genuinely complete file would have been moved out of
  /// staging by `/v1/complete` and could not be here at all, whereas a
  /// full-length leftover almost always means the process died mid-write — and
  /// trusting it would skip every byte, then fail the digest check much later
  /// with a confusing error. Correct beats cheap.
  Future<int> _resumePoint(
    _LinkState state,
    FileEntry entry,
    String path,
  ) async {
    final tracked = state.received[entry.id];
    if (tracked != null) return tracked > entry.size ? entry.size : tracked;

    final length = await store.existingBytes(state.sessionId, entry.id);
    if (entry.size > 0 && length >= entry.size) {
      // Torn preallocation. Act on the decision now rather than leaving a
      // poisoned file for the first PUT to trip over: `stage` deliberately never
      // shrinks an existing `.part` (that would destroy a resumable prefix), so
      // the truncation has to happen here.
      coreLog.info(
        'offer: discarding a torn ${entry.id} at $length bytes '
        '(declared ${entry.size}); restarting the file',
      );
      await _truncate(path, 0);
      return 0;
    }
    return length;
  }

  /// Shrinks [path] to [length] bytes without losing what is already there.
  ///
  /// `FileMode.append` never truncates on open and ftruncate only removes the
  /// tail, so this preserves a resume prefix and is safe to call at any time.
  static Future<void> _truncate(String path, int length) async {
    try {
      final file = File(path);
      if (!await file.exists()) return;
      final raf = await file.open(mode: FileMode.append);
      try {
        raf.truncateSync(length);
      } finally {
        await raf.close();
      }
    } on FileSystemException catch (e) {
      coreLog.warning('could not truncate $path to $length', e);
    }
  }

  // ---------------------------------------------------------------------------
  // PUT /v1/file/{id}   — the hot path
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _putFile(PeerLink link, _LinkState state, ApiRequest request) async {
    if (state.cancelled) {
      throw PeerException(ApiError.cancelled, 'session was cancelled');
    }
    final id = _fileId(request.path);
    final entry = state.entries[id];
    if (entry == null) {
      throw PeerException(ApiError.badRequest, 'no offered file with id "$id"');
    }
    final staged = state.staged[id];
    if (staged == null) {
      throw PeerException(
        ApiError.internal,
        'file "$id" was accepted but not staged',
      );
    }
    final declared = _declaredDigest(entry, request);

    // How much do we believe we have? Our own accounting from this connection
    // wins; the file length is only a fallback for a reconnect, and it is only
    // trustworthy because every interrupted PUT shrank its `.part` back to the
    // bytes that actually landed.
    var tracked =
        state.received[id] ??
        await store.existingBytes(state.sessionId, entry.id);
    if (entry.size > 0 &&
        tracked >= entry.size &&
        !state.completed.contains(id)) {
      // A full-length staged file we did not complete ourselves: the process was
      // killed mid-write. Trusting the length would skip every remaining byte
      // and only fail much later at `/v1/complete`, so start over instead.
      coreLog.info('PUT $id: discarding a torn preallocated .part');
      await _truncate(staged.path, 0);
      tracked = 0;
    }
    final start = _requestedOffset(request, tracked);
    if (start != tracked) {
      // 409 rather than an exception: the body of the response is how the
      // sender learns where to resume from. `putStream` turns the status into a
      // PeerException(conflict) on the far side, and `SenderSession` then asks
      // `GET /v1/file/{id}` for the authoritative offset — no string parsing of
      // the message needed.
      //
      // Note the request body is deliberately *not* drained here: it could be a
      // terabyte, and reading it to answer "wrong offset" is exactly the
      // amplification a hostile peer wants. The transport is responsible for
      // deciding whether that means "close the connection" (the correct answer
      // for HTTP/1.1 with an unread body) or can pipeline another request.
      return ApiResponse.json({
        'error': ApiError.conflict,
        'resumeFrom': tracked,
        'message': 'client offered offset $start, $tracked bytes are staged',
      }, status: 409);
    }

    if (tracked >= entry.size) {
      // Already complete in this session: re-verify from disk rather than
      // trusting anything the sender said.
      final actual = await _digestFile(staged.path);
      if (!_digestsMatch(declared, actual)) {
        await _dropStaged(state, id, staged);
        return _mismatch(id, declared, actual);
      }
      state.digests[id] = actual;
      return _received(id, actual, entry.size);
    }

    final digest = _Sha256Digest(sha256.newHashSink());

    // SHA-256 cannot be resumed. FIPS 180-4 specifies whole-message hashing
    // only, so there is no way to reconstruct the compression state after N
    // bytes and carry on; the only correct option is to re-read the prefix we
    // already have and fold it in first. That costs one local disk pass and
    // zero extra network traffic, and a resumed transfer is rare enough that the
    // trade is obviously right.
    if (start > 0) {
      await for (final chunk in File(staged.path).openRead(0, start)) {
        digest.add(chunk);
      }
      coreLog.fine('PUT $id: re-hashed $start stored bytes before resuming');
    }

    final file = File(staged.path);
    // `FileMode.append` is the only mode that neither truncates the received
    // prefix nor refuses positioned writes: dart:io maps it to
    // O_RDWR|O_CREAT|O_APPEND and `RandomAccessFile` honours `setPositionSync`.
    // (O_WRONLY without O_TRUNC does not exist in the FileMode enum.)
    final raf = await file.open(mode: FileMode.append);
    var written = start;
    state.activeWrites.add(id);
    try {
      // Restore the preallocation that a previous interruption's shrink-to-offset
      // removed. ftruncate upwards is O(1) and allocates extents once, instead
      // of making the filesystem grow the file a block at a time.
      if (raf.lengthSync() != entry.size) raf.truncateSync(entry.size);
      raf.setPositionSync(start);

      await for (final chunk in request.body) {
        if (state.cancelled) {
          throw PeerException(ApiError.cancelled, 'cancelled mid-transfer');
        }
        if (written + chunk.length > entry.size) {
          throw PeerException(
            ApiError.tooLarge,
            '"$id" is longer than the declared ${entry.size} bytes',
          );
        }
        raf.setPositionSync(written);
        // Awaiting the write is the backpressure: while the kernel has not
        // accepted these bytes we do not ask for the next chunk, so a fast disk
        // cannot outrun a slow socket and pile up in the Dart heap.
        await raf.writeFrom(chunk);
        digest.add(chunk);
        written += chunk.length;
        state.received[id] = written;
        // Reported per chunk rather than throttled here: a 4 MiB chunk is
        // already coarse enough that the UI sees a handful of updates per
        // second, and the listener is free to coalesce further.
        onProgress?.call(link, id, written, entry.size);
      }
    } finally {
      state.activeWrites.remove(id);
      try {
        await raf.flush();
        // Shrink to the bytes that actually landed. This is what makes
        // `store.existingBytes` (a file length read) an honest resume oracle:
        // without it the preallocated `.part` would still claim the full size.
        raf.truncateSync(written);
      } on FileSystemException catch (e) {
        coreLog.warning('could not finalise staged length for $id', e);
      }
      await raf.close();
    }

    if (written != entry.size) {
      // The body ended early — a truncated sender or a cut network. The staged
      // file is now at its true resume point, so 409 with that offset lets the
      // sender continue instead of starting over.
      coreLog.info('PUT $id: short body, $written of ${entry.size} bytes');
      return ApiResponse.json({
        'error': ApiError.conflict,
        'resumeFrom': written,
        'message': 'body ended after $written of ${entry.size} bytes',
      }, status: 409);
    }

    final actual = await digest.hex();
    if (!_digestsMatch(declared, actual)) {
      // Corrupt or lying peer: throw the bytes away so a retry starts clean
      // rather than failing forever on a poisoned staged file.
      await _dropStaged(state, id, staged);
      return _mismatch(id, declared, actual);
    }

    state.digests[id] = actual;
    state.received[id] = written;
    state.completed.add(id);
    coreLog.fine('PUT $id: $written bytes, sha256 ok');
    return _received(id, actual, written);
  }

  ApiResponse _received(String id, String digest, int bytes) =>
      ApiResponse.json({
        'sha256Match': true,
        'sha256': digest,
        'bytes': bytes,
        'id': id,
      });

  ApiResponse _mismatch(String id, String? expected, String actual) =>
      ApiResponse.json({
        'error': ApiError.hashMismatch,
        'sha256Match': false,
        'expected': expected,
        'actual': actual,
        'id': id,
        'message': 'sha256 mismatch for "$id"',
      }, status: 422);

  Future<void> _dropStaged(
    _LinkState state,
    String id,
    StagedFile staged,
  ) async {
    state.staged.remove(id);
    state.received.remove(id);
    state.digests.remove(id);
    // Forget it was ever "complete" too, or a later PUT would trust the
    // (now deleted) file's length as a resume point.
    state.completed.remove(id);
    try {
      await store.discard(staged);
    } on Object catch (e) {
      coreLog.warning('discard after digest mismatch failed for $id', e);
    }
  }

  /// The digest the *sender* claims it is sending, cross-checked between the
  /// offer and the per-request header.
  ///
  /// A disagreement between the two is itself suspicious — a peer that puts one
  /// digest in the manifest and another in the header is trying to get past the
  /// offer-time check.
  String? _declaredDigest(FileEntry entry, ApiRequest request) {
    final header = request.header(Header.sha256)?.trim().toLowerCase() ?? '';
    final inOffer = entry.sha256?.trim().toLowerCase() ?? '';
    if (header.isNotEmpty && inOffer.isNotEmpty && header != inOffer) {
      throw PeerException(
        ApiError.badRequest,
        'header digest disagrees with the offered digest',
      );
    }
    final value = header.isNotEmpty ? header : inOffer;
    if (value.isEmpty) return null;
    if (value.length != 64 || !_isHex(value)) {
      throw PeerException(ApiError.badRequest, 'malformed sha256');
    }
    return value;
  }

  static bool _isHex(String s) {
    for (final unit in s.codeUnits) {
      final digit = unit >= 0x30 && unit <= 0x39;
      final lower = unit >= 0x61 && unit <= 0x66;
      if (!digit && !lower) return false;
    }
    return true;
  }

  static bool _digestsMatch(String? declared, String actual) =>
      declared == null || declared == actual;

  /// `Content-Range: bytes=N-` (open-ended, which is all this protocol uses) or
  /// 0 when the header is absent.
  ///
  /// Refuses a reversed range (`bytes=5-2`) and anything that is not an
  /// open-ended byte range, rather than guessing: guessing here means writing at
  /// an offset the sender did not intend.
  int _requestedOffset(ApiRequest request, int staged) {
    final raw = request.header(Header.contentRange)?.trim();
    if (raw == null || raw.isEmpty) return 0;
    final match = RegExp(r'^bytes\s*=\s*(\d+)\s*-\s*(\d*)$').firstMatch(raw);
    if (match == null) {
      throw PeerException(ApiError.badRequest, 'unsupported Content-Range');
    }
    final start = int.parse(match.group(1)!);
    final end = match.group(2);
    if (start > staged) return start; // legitimate forward resume
    if (end != null && end.isNotEmpty) {
      throw PeerException(
        ApiError.badRequest,
        'closed Content-Range not supported',
      );
    }
    return start;
  }

  // ---------------------------------------------------------------------------
  // GET /v1/file/{id}
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _fileStatus(_LinkState state, ApiRequest request) async {
    final id = _fileId(request.path);
    final entry = state.entries[id];
    if (entry == null) {
      throw PeerException(ApiError.badRequest, 'no offered file with id "$id"');
    }
    var received =
        state.received[id] ??
        await store.existingBytes(state.sessionId, entry.id);
    if (received > entry.size) received = entry.size;
    return ApiResponse.json({
      'id': id,
      'name': entry.name,
      'size': entry.size,
      'received': received,
      'complete': received >= entry.size,
      'sha256': state.digests[id],
    });
  }

  // ---------------------------------------------------------------------------
  // POST /v1/complete
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _complete(PeerLink link, _LinkState state, ApiRequest request) async {
    final report = _parseReport(await _readJson(request));
    if (report.sessionId.isNotEmpty && report.sessionId != state.sessionId) {
      throw PeerException(
        ApiError.unknownSession,
        'report is for "${report.sessionId}", not "${state.sessionId}"',
      );
    }
    if (report.cancelled) {
      return await _cancelNow(state);
    }

    // fileId -> (claimedDigest, claimedBytes)
    final reported = <String, (String, int)>{};
    for (final (id, sha, bytes) in report.files) {
      reported[id] = (sha, bytes);
    }
    final failures = <String>[];

    // Everything WE staged is verified, whether or not the report mentions it:
    // the report is the sender's account of what it did, not the truth.
    for (final id in List<String>.of(state.staged.keys)) {
      final staged = state.staged[id]!;
      final claim = reported[id];
      try {
        // Length and digest come from the disk, not from the report.
        final length = await File(staged.path).length();
        if (length != staged.size) {
          failures.add('$id: staged $length of ${staged.size} bytes');
          continue;
        }
        if (claim != null && claim.$2 != 0 && claim.$2 != length) {
          failures.add('$id: sender claims ${claim.$2} bytes, staged $length');
          continue;
        }
        final actual = await _digestFile(staged.path);
        final declared = _firstNonEmpty([
          if (claim != null) claim.$1,
          state.entries[id]?.sha256,
        ])?.trim().toLowerCase();
        if (declared != null && declared.isNotEmpty && declared != actual) {
          failures.add(
            '$id: sha256 mismatch (claimed $declared, on disk $actual)',
          );
          continue;
        }
        final path = await store.commit(staged, state.sessionId);
        state.committed[id] = path;
        coreLog.info('complete: committed $id -> $path');
      } on PeerException catch (e) {
        failures.add('$id: ${e.message.isEmpty ? e.code : e.message}');
      } on FileSystemException catch (e) {
        failures.add('$id: ${e.osError?.message ?? e.message}');
      }
    }

    // Anything the report claims but we never staged: the sender thinks it sent
    // bytes we have no record of accepting.
    for (final (id, _, _) in report.files) {
      if (!state.staged.containsKey(id)) {
        failures.add('$id: reported complete but never staged here');
      }
    }

    final result = CompletionResult(ok: failures.isEmpty, failures: failures);
    if (result.ok) {
      state.clearSession();
    } else {
      coreLog.warning('complete: ${failures.length} failures');
    }
    onComplete?.call(link, result);
    return ApiResponse.json(result.toJson());
  }

  static String? _firstNonEmpty(List<String?> values) {
    for (final v in values) {
      if (v != null && v.isNotEmpty) return v;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // POST /v1/cancel
  // ---------------------------------------------------------------------------

  Future<ApiResponse> _cancel(_LinkState state, ApiRequest request) async {
    // Drain the body so the transport can keep the connection alive for a
    // retry, but do not care what it said.
    try {
      await _readJson(request);
    } on PeerException {
      // A malformed cancel is still a cancel.
    }
    return _cancelNow(state);
  }

  Future<ApiResponse> _cancelNow(_LinkState state) async {
    state.cancelled = true;
    for (final staged in state.staged.values) {
      try {
        await store.discard(staged);
      } on Object catch (e) {
        coreLog.warning('discard during cancel failed', e);
      }
    }
    final discarded = state.staged.length;
    state.clearSession();
    coreLog.info('cancel: discarded $discarded staged files');
    return ApiResponse.json({'cancelled': true});
  }

  // ---------------------------------------------------------------------------
  // Body / model parsing
  // ---------------------------------------------------------------------------

  /// Reads a JSON object body, refusing anything over [limit].
  ///
  /// A hostile peer controls both `Content-Length` and the actual byte count, so
  /// the declared length is only used as a fast rejection; the running total is
  /// what actually enforces the cap. Without this a 4 GiB "offer" would be
  /// buffered in the Dart heap before any validation ran.
  Future<Map<String, dynamic>> _readJson(
    ApiRequest request, {
    int? limit,
  }) async {
    final cap = limit ?? maxJsonBodyBytes;
    final declared = request.contentLength;
    if (declared != null && declared > cap) {
      throw PeerException(
        ApiError.badRequest,
        'body of $declared bytes exceeds $cap',
      );
    }

    final builder = BytesBuilder(copy: false);
    var total = 0;
    try {
      await for (final chunk in request.body) {
        total += chunk.length;
        if (total > cap) {
          throw PeerException(ApiError.badRequest, 'body exceeds $cap bytes');
        }
        builder.add(chunk);
      }
    } on PeerException {
      rethrow;
    } on Object {
      // The peer hung up mid-body.
      throw PeerException(ApiError.badRequest, 'truncated request body');
    }

    if (total == 0) return const <String, dynamic>{};

    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(builder.takeBytes()));
    } on FormatException catch (e) {
      throw PeerException(ApiError.badRequest, 'invalid JSON: ${e.message}');
    }
    if (decoded is! Map<String, dynamic>) {
      throw PeerException(ApiError.badRequest, 'body is not a JSON object');
    }
    return decoded;
  }

  Offer _parseOffer(Map<String, dynamic> body) {
    final Offer offer;
    try {
      offer = Offer.fromJson(body);
    } on PeerException {
      rethrow;
    } on Object {
      // `Offer.fromJson` does unchecked casts (`json['sessionId'] as String`,
      // `e as Map`); a peer that sends the wrong shape gets a 400, not a 500.
      throw PeerException(ApiError.badRequest, 'malformed offer');
    }
    if (offer.sessionId.isEmpty) {
      throw PeerException(ApiError.badRequest, 'offer has no session id');
    }
    return offer;
  }

  CompletionReport _parseReport(Map<String, dynamic> body) {
    final CompletionReport report;
    try {
      report = CompletionReport.fromJson(body);
    } on PeerException {
      rethrow;
    } on Object {
      throw PeerException(ApiError.badRequest, 'malformed completion report');
    }
    return report;
  }

  String _fileId(String path) {
    final prefix = '${Api.file}/';
    final raw = path.substring(prefix.length);
    if (raw.isEmpty || raw.contains('/')) {
      throw PeerException(ApiError.badRequest, 'missing file id');
    }
    final String decoded;
    try {
      decoded = Uri.decodeComponent(raw);
    } on FormatException {
      throw PeerException(ApiError.badRequest, 'malformed file id');
    }
    // The id becomes a filename in `LocalFileStore.stage`, so it goes through
    // the same sanitiser as any other peer-supplied component. Belt and braces:
    // the earlier slash check already rejects `%2F`-style attempts.
    return LocalFileStore.sanitiseComponent(decoded, 'file id');
  }

  // ---------------------------------------------------------------------------
  // Digests
  // ---------------------------------------------------------------------------

  /// SHA-256 over a whole file, read from disk in chunks.
  ///
  /// Used by `/v1/complete` and by the "already complete" short-circuit in
  /// [Api.putStream]'s counterpart. Re-reading is deliberate: the point is to
  /// trust the bytes on disk rather than anything the peer or the in-memory
  /// hasher said.
  Future<String> _digestFile(String path) async {
    final digest = _Sha256Digest(sha256.newHashSink());
    await for (final chunk in File(path).openRead()) {
      digest.add(chunk);
    }
    return digest.hex();
  }

  Future<void> _shrinkInterrupted(_LinkState state) async {
    for (final entry in state.received.entries) {
      // A `PUT` that is still running owns its file and truncates in its own
      // `finally`; two truncates racing would be a correctness hazard, not just
      // untidy.
      if (state.activeWrites.contains(entry.key)) continue;
      final staged = state.staged[entry.key];
      if (staged == null) continue;
      final received = entry.value;
      if (received >= staged.size) continue;
      await _truncate(staged.path, received);
      coreLog.info(
        'disconnect: shrunk ${entry.key} to its $received staged bytes '
        'for resume',
      );
    }
  }
}

/// Per-connection protocol state.
///
/// Deliberately *not* persisted: pairing is per TLS session, and everything a
/// resumed transfer needs beyond that lives on disk (the `.part` files) rather
/// than here.
class _LinkState {
  bool paired = false;
  bool cancelled = false;
  bool detached = false;

  String sessionId = '';
  Offer? offer;

  /// Offered file id -> entry, for every accepted file.
  final Map<String, FileEntry> entries = {};

  /// Offered file id -> preallocated staging handle.
  final Map<String, StagedFile> staged = {};

  /// Offered file id -> bytes that actually landed. The in-memory resume oracle.
  final Map<String, int> received = {};

  /// Ids we finished and digest-verified in *this* connection.
  ///
  /// The distinction matters for the "is this a completed file or a torn one?"
  /// heuristic in `_putFile`: only a file this connection finished may be
  /// trusted to be at its full length.
  final Set<String> completed = {};

  /// Offered file id -> digest we computed ourselves.
  final Map<String, String> digests = {};

  /// Offered file id -> final absolute path after a successful commit.
  final Map<String, String> committed = {};

  /// Ids with a `PUT` currently streaming. Prevents the disconnect cleanup from
  /// truncating a file that is actively being written.
  final Set<String> activeWrites = {};

  /// Starts (or resumes) a session.
  ///
  /// Re-offering the *same* session id keeps everything: that is exactly the
  /// resume signal, and throwing the staged handles away here would restart the
  /// transfer from zero.
  void beginSession(String id, Offer newOffer) {
    if (id == sessionId && offer != null) return;
    sessionId = id;
    offer = newOffer;
    entries.clear();
    staged.clear();
    received.clear();
    completed.clear();
    digests.clear();
    committed.clear();
    cancelled = false;
  }

  void clearSession() {
    offer = null;
    entries.clear();
    staged.clear();
    received.clear();
    completed.clear();
    digests.clear();
    committed.clear();
  }
}

/// Incremental SHA-256 over bytes that arrive one slice at a time.
///
/// Two properties matter here:
///
///  * **Streaming.** `newHashSink()` on `Sha256()` returns a sink that folds
///    each `add` into the compression state and keeps only a 64-byte block
///    buffer. The alternative — collecting slices and calling
///    `Sha256().hash(allOfThem)` — materialises the entire file in the Dart
///    heap, which for a 1 TiB transfer is a 1 TiB heap. (The generic
///    `HashSink` in `package:cryptography` is a buffering `BytesBuilder`; the
///    `DartSha256` override returned by the `Sha256()` factory is not.)
///  * **Async finalisation.** `HashSink.hash()` is the only portable way to get
///    bytes out (the synchronous `hashSync()` lives on the Dart-specific
///    subclass), so [hex] is a `Future` and the two call sites that need it are
///    already async.
class _Sha256Digest {
  _Sha256Digest(this._sink);

  final HashSink _sink;
  var _closed = false;
  String? _hex;

  void add(List<int> bytes) {
    if (bytes.isEmpty || _closed) return;
    _sink.add(bytes);
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _sink.close();
  }

  /// Lowercase hex digest, lowercased. Idempotent; must follow [close].
  Future<String> hex() async {
    final cached = _hex;
    if (cached != null) return cached;
    if (!_closed) close();
    return _hex = _hexOf((await _sink.hash()).bytes);
  }
}

/// Table used to render a digest as lowercase hex without pulling in
/// `package:convert`.
const String _hexDigits = '0123456789abcdef';

/// Lowercase hex of [bytes].
///
/// Note the empty [StringBuffer]: its constructor takes *content*, not capacity,
/// so `StringBuffer(n)` would prepend the decimal form of `n` to the digest.
/// `writeCharCode` avoids allocating a one-character String per nibble.
String _hexOf(List<int> bytes) {
  final out = StringBuffer();
  for (final b in bytes) {
    out.writeCharCode(_hexDigits.codeUnitAt((b >> 4) & 0x0f));
    out.writeCharCode(_hexDigits.codeUnitAt(b & 0x0f));
  }
  return out.toString();
}
