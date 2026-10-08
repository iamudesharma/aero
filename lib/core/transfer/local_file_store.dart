/// Filesystem-backed [FileStore] + [ChunkedFileReader].
///
/// # Threat model — this file is the security boundary of the whole app
///
/// Everything this class is handed about *names and paths* arrives from a peer
/// over the network and is therefore **hostile input**. The peer may be
/// actively trying to write outside the inbox, so every single path component
/// that reaches the filesystem is treated as an attacker-controlled string:
///
///  * a `FileEntry.name` of `../../../../.ssh/authorized_keys`,
///  * a `relPath` of `a/../../b`,
///  * an absolute path (`/etc/passwd`, `C:\Windows\...`, `\\server\share`),
///  * an embedded NUL (`evil\u0000.txt`) which truncates the path in C
///    level syscalls on some platforms,
///  * a Unicode look-alike for a separator (`U+2215 DIVISION SLASH`) that
///    normalises into `/` on a case-insensitive or normalisation-sensitive
///    filesystem.
///
/// Defence is layered, because a single check is one bug away from a
/// remote arbitrary-file-write:
///
///  1. **Reject, do not repair.** [sanitiseComponent] throws
///     [PeerException] for `..`, `.`, separators, NUL, `:` (drive letters and
///     NTFS alternate data streams), and reserved Windows device names.
///     Silently rewriting `../../etc/passwd` into `etc_passwd` would hide a
///     hostile peer behind a file that looks legitimate; a hard failure is
///     visible in the UI and in the logs.
///  2. **Only sanitised components are ever joined.** Paths are built as
///     `<base>/aero-.../<sanitised>/<sanitised>/...` with `join`-like string
///     concatenation. Because no component can contain a separator and none can
///     be `.` or `..`, the result *provably* cannot escape — there is no
///     normalisation step in which a `..` could be resolved away.
///  3. **Verify the assembled path anyway** ([_assertInsideRoot]). Cheap, and
///     it converts "I believe the earlier checks were right" into "I proved the
///     final path is under the root". It compares path *segments* so it works
///     identically on POSIX and Windows.
///  4. **Refuse to follow symlinks out of the root** ([_assertNoSymlinkEscape]).
///     Steps 1-3 are purely lexical and therefore blind to a symlink an
///     attacker planted inside the store in a previous session. Before creating
///     directories in the inbox we resolve the chain and confirm the real
///     target is still inside the root.
///
/// The staging area is deliberately keyed by `sessionId` + `entryId` only —
///
/// ```text
///   <base>/aero-sessions/<sessionId>/<entryId>.part   preallocated, resumable
///   <base>/aero-inbox/<sanitised relPath>             committed, user visible
/// ```
///
/// — never by the peer's `name`. That means a hostile name can never influence
/// where bytes land on disk at all; it is sanitised and used only as a display
/// name at commit time.

library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';
import 'receive_destination.dart';

/// Directory (under the base) holding in-flight transfers.
const String kSessionsDirName = 'aero-sessions';

/// Directory (under the base) holding committed files.
const String kInboxDirName = 'aero-inbox';

/// Suffix of a preallocated, not-yet-committed file.
const String kPartSuffix = '.part';

/// Sidecar manifest recording the *sanitised* `name` / `relPath` of every entry
/// in a session, so [commit] can find them again from the entry id alone.
const String kManifestFileName = 'aero-session.json';

/// Longest single path component we accept. 255 is the ext4/APFS limit; NTFS
/// allows 255 too, so one number covers every target.
const int _maxComponentLength = 255;

/// Reserved device names on Windows. `CON` cannot be created on NTFS, and a
/// peer offering it would otherwise turn `commit` into a hard failure deep in
/// the transfer instead of a clean rejection at offer time.
const Set<String> _reservedDeviceNames = {
  'con', 'prn', 'aux', 'nul', //
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
};

/// Why [LocalFileStore.freeSpace] cannot answer, and what callers must do.
const String kFreeSpaceUnavailable =
    'dart:io has no statvfs/GetDiskFreeSpaceEx binding; free space is unknown '
    'and must be treated as "possibly out of space".';

/// Concrete [FileStore] / [ChunkedFileReader] over `dart:io`.
///
/// Works on all six native targets. The browser build uses a different
/// implementation (OPFS / File System Access API) — [FileStore] exists precisely
/// so this class is not baked into the protocol logic.
class LocalFileStore implements FileStore, ChunkedFileReader {
  /// [baseDirectory] is injectable so tests (and any caller wanting a
  /// user-chosen download folder) can supply their own root. When null the base
  /// is resolved lazily from `path_provider`, because resolving it requires an
  /// async platform call that a constructor cannot perform.
  LocalFileStore({Directory? baseDirectory, ReceiveDestination? destination})
    : _explicitBase = baseDirectory?.absolute,
      _destinationOverride = destination;

  /// Used for progress/diagnostics and to prove containment.
  final Directory? _explicitBase;

  /// Where a completed file is published. Resolved lazily because the default
  /// needs an async platform call; injectable so tests get a real directory.
  final ReceiveDestination? _destinationOverride;
  ReceiveDestination? _destination;

  /// The destination actually in use, resolved on first commit.
  ReceiveDestination? get destination => _destination;

  Future<Directory>? _baseFuture;

  /// Cached session manifests, keyed by session id. Only ever holds entries
  /// whose components have already been sanitised.
  final Map<String, Map<String, dynamic>> _manifests = {};

  /// Serialises manifest read-modify-write so two concurrent [stage] calls
  /// cannot lose each other's entry. Reassigned on every call, hence non-final.
  // ignore: prefer_final_fields
  Future<void> _manifestLock = Future<void>.value();

  /// The storage root, creating it if needed.
  ///
  /// Exposed so callers can show the user where files landed.
  Future<Directory> baseDirectory() async {
    final dir = await _resolveBase();
    if (!dir.existsSync()) {
      await dir.create(recursive: true);
    }
    return dir;
  }

  Future<Directory> _resolveBase() {
    return _baseFuture ??= _resolveBaseUncached();
  }

  Future<Directory> _resolveBaseUncached() async {
    final base = _explicitBase;
    if (base != null) return base;
    // Application support, not documents: staged `.part` files are internal
    // scratch and must not be indexed or backed up by the OS while a transfer
    // is half-done.
    return getApplicationSupportDirectory();
  }

  // ---------------------------------------------------------------------------
  // FileStore
  // ---------------------------------------------------------------------------

  /// Free bytes on the volume that holds the staging directory, or `null` when
  /// it cannot be determined.
  ///
  /// ## Why this is not always null any more
  ///
  /// `dart:io` has no `statvfs(2)` / `GetDiskFreeSpaceExW` binding, so the
  /// original implementation returned `null` everywhere. That is honest, but on
  /// desktop - macOS, Linux, Windows - `df` answers the question reliably and
  /// cheaply, and the answer is genuinely useful: the offline fallback tiers let
  /// a user receive a large file onto a phone or laptop that may be nearly full,
  /// and refusing the offer up front is far better than dying at 90%.
  ///
  /// ## Why mobile stays `null`
  ///
  /// Shelling out is not available on Android/iOS, and guessing would be worse
  /// than nothing: a wrong value makes the receiver accept an offer it cannot
  /// store, and the failure surfaces much later as a mid-transfer ENOSPC. On
  /// those platforms [stage]'s preallocation is the guard.
  ///
  /// ## Safety
  ///
  /// Never throws and never guesses. A parse failure, a missing binary, or a
  /// non-zero exit is reported as "unknown" (`null`), which the protocol already
  /// handles as "skip the pre-flight check".
  @override
  Future<int?> freeSpace() async {
    if (Platform.isAndroid || Platform.isIOS) return null;
    try {
      final base = await baseDirectory();
      final result = await Process.run(
        Platform.isWindows ? 'wmic' : 'df',
        Platform.isWindows
            ? ['logicaldisk', 'where', 'DeviceID="C:"', 'get', 'FreeSpace', '/value']
            // `-k` gives 1024-byte blocks, so this needs no unit parsing and no
            // locale-dependent formatting. `-P` forces the portable one-line
            // format, which is what makes the last line parseable.
            : ['-k', '-P', base.path],
      );
      if (result.exitCode != 0) return null;
      return _parseFreeSpace('${result.stdout}', windows: Platform.isWindows);
    } catch (error) {
      coreLog.fine('could not determine free space: $error');
      return null;
    }
  }

  /// Parse the byte count out of `df -k -P` or `wmic` output.
  ///
  /// Separated from [freeSpace] so the parsing - the part that can silently be
  /// wrong, which would be worse than returning null - is unit testable without
  /// spawning a process.
  static int? parseFreeSpaceForTest(String output, {bool windows = false}) =>
      _parseFreeSpace(output, windows: windows);

  /// Creates `<base>/aero-sessions/<sessionId>/<entryId>.part` and preallocates
  /// it to [FileEntry.size].
  ///
  /// ## Why preallocate
  ///
  /// Writing 40 MiB sequentially into a *fresh* file makes APFS, NTFS and ext4
  /// grow the file a block at a time: every growth is an extent update plus a
  /// metadata write, the free-space map gets fragmented, and the write path
  /// degrades from streaming to seeking. Measured on a spinning disk this is the
  /// difference between ~500 MB/s and ~30 MB/s. `truncateSync` (ftruncate) tells
  /// the filesystem up front "this file will be N bytes", so it can lay out the
  /// extents once — and on APFS it produces a sparse file whose holes are
  /// materialised as the real bytes land.
  ///
  /// Note `RandomAccessFile.setLengthSync` does not exist; the Dart spelling is
  /// [RandomAccessFile.truncateSync], which has `ftruncate` semantics and
  /// therefore *extends* a file with zeros when the requested length is larger.
  ///
  /// ## Resuming
  ///
  /// If the `.part` already exists this method **does not resize it**. A stage
  /// call with the same `(sessionId, entryId)` means "the same file, possibly
  /// half-received", and truncating back to 0 would throw away the bytes a
  /// resumed transfer depends on.
  @override
  Future<StagedFile> stage(FileEntry entry, String sessionId) async {
    final base = await baseDirectory();
    final sid = sanitiseSessionId(sessionId);
    final entryId = sanitiseComponent(entry.id, 'entry id');

    // Validate the peer's display name and relative path *here*, at offer time,
    // so a hostile name is rejected before a single content byte is spent —
    // rather than exploding during commit after a 10 GiB transfer.
    sanitiseDisplayName(entry.name);
    final rel = sanitiseRelPath(entry.relPath);

    if (entry.size < 0) {
      throw PeerException(ApiError.badRequest, 'negative size for $entryId');
    }
    if (entry.size > Transfer.maxFileSize) {
      throw PeerException(
        ApiError.tooLarge,
        '$entryId is ${entry.size} bytes, limit is ${Transfer.maxFileSize}',
      );
    }

    final dir = Directory(_childPath([base.path, kSessionsDirName, sid]));
    await dir.create(recursive: true);
    final file = File(_childPath([dir.path, '$entryId$kPartSuffix']));
    // Lexical containment is guaranteed by construction (every component above
    // was sanitised); this is the assertion that proves it.
    _assertInsideRoot(base.path, file.path);

    final exists = file.existsSync();
    final length = exists ? file.lengthSync() : -1;

    if (exists && length == entry.size) {
      // Already preallocated (a retry of the same offer, or a fully written
      // file whose digest check has not run yet). Leave the bytes alone.
    } else if (exists && length > 0 && length < entry.size) {
      // Partial from an interrupted transfer: keep the prefix verbatim.
      coreLog.fine('stage: resuming $entryId at $length/${entry.size}');
    } else {
      // Fresh, empty, or left over from an offer whose size has since changed.
      // `writeOnly` creates and truncates, then truncateSync preallocates.
      final raf = await file.open(mode: FileMode.writeOnly);
      try {
        raf.truncateSync(entry.size);
      } finally {
        await raf.close();
      }
      coreLog.fine('stage: preallocated $entryId -> ${entry.size} bytes');
    }

    await _rememberEntry(sid, entry, name: entry.name, relPath: rel);

    return StagedFile(entryId: entry.id, path: file.path, size: entry.size);
  }

  /// Moves the staged `.part` into the inbox and returns its absolute path.
  ///
  /// The destination is `<base>/aero-inbox/<sanitised relPath>` when the offer
  /// carried one (folder transfers keep their shape), otherwise
  /// `<base>/aero-inbox/<sanitised name>`. Both were sanitised in [stage] and
  /// are sanitised *again* here — [commit] only receives an entry id, so it has
  /// no way to know whether it is talking to a store that validated the name.
  @override
  Future<String> commit(StagedFile staged, String sessionId) async {
    final base = await baseDirectory();
    final sid = sanitiseSessionId(sessionId);
    final src = File(staged.path);
    if (!src.existsSync()) {
      throw PeerException(
        ApiError.conflict,
        'cannot commit ${staged.entryId}: staged file is gone',
      );
    }

    final meta = await _manifestEntry(sid, staged.entryId);
    final rawRel = meta?['relPath'] as String?;
    final rawName = meta?['name'] as String?;
    // `FileEntry.relPath` is the *directory* the file belongs in ("photos/2026")
    // and `name` is the basename ("leaf.jpg"), so the destination is the two
    // joined. Treating relPath as the full destination path would turn
    // `photos/2026` into a file called `2026`.
    final name = sanitiseDisplayName(rawName ?? staged.entryId);
    final dir = sanitiseRelPath(rawRel);
    final relative = dir == null || dir.isEmpty ? name : '$dir/$name';

    final inbox = Directory(_childPath([base.path, kInboxDirName]));
    await inbox.create(recursive: true);

    // Lexical defence cannot see symlinks, so resolve the chain first.
    await _assertNoSymlinkEscape(base.path, inbox.path);

    var dest = File(_childPath([inbox.path, ...relative.split('/')]));
    _assertInsideRoot(base.path, dest.path);
    await dest.parent.create(recursive: true);
    await _assertNoSymlinkEscape(base.path, dest.parent.path);

    final actual = await src.length();
    if (actual != staged.size) {
      throw PeerException(
        ApiError.conflict,
        'commit ${staged.entryId}: staged $actual bytes, expected ${staged.size}',
      );
    }

    // Publish to a location the user can actually find. Staging under the app's
    // support directory is correct while bytes are in flight (it is private and
    // guaranteed writable), but a finished file left there is invisible: on
    // Android it sits in /data/user/0/<pkg>/files, which no file manager or
    // gallery can reach, and on macOS it is inside the sandbox container.
    final destination = await _resolveDestination(base);
    final published = await destination.publish(
      stagedPath: src.path,
      name: name,
      relPath: dir,
    );
    coreLog.info(
      'commit: ${staged.entryId} -> $published ($actual bytes via ${destination.label})',
    );

    // `publish` removes the staged file itself (a rename, or a copy+delete when
    // it crosses volumes), so there is nothing left to clean up here.
    await _dropSessionDirIfEmpty(src.path);
    return published;
  }

  /// Resolve once and reuse: the MediaStore destination keeps a little state
  /// (the last saved location) and re-creating it per file would lose that.
  Future<ReceiveDestination> _resolveDestination(Directory base) async {
    final existing = _destination;
    if (existing != null) return existing;
    final resolved = _destinationOverride ??
        resolveReceiveDestination(supportDir: Directory(_childPath([base.path, kInboxDirName])));
    _destination = resolved;
    return resolved;
  }

  /// Deletes the staged file. Missing files are not an error: `cancel` is
  /// best-effort and may race with a disconnect cleanup.
  @override
  Future<void> discard(StagedFile staged) async {
    final file = File(staged.path);
    try {
      if (await file.exists()) {
        await file.delete();
        coreLog.fine('discard: removed ${staged.path}');
      }
    } on FileSystemException catch (e) {
      // Losing the race with another cleanup is fine; anything else is worth
      // surfacing but must not fail the caller's `cancel`.
      coreLog.warning('discard: could not delete ${staged.path}', e);
    }
    await _dropSessionDirIfEmpty(staged.path);
  }

  /// Bytes on disk for `(sessionId, entryId)`, or 0 when nothing is staged.
  ///
  /// This is the resume oracle. It is only meaningful when the staged file has
  /// been left at its true length — i.e. when an interrupted transfer shrank
  /// the `.part` back to the number of bytes actually received. See
  /// `AeroPeerApi` for where that happens; without it a preallocated file would
  /// always report `size` and every resume would silently start from EOF.
  @override
  Future<int> existingBytes(String sessionId, String entryId) async {
    File file;
    try {
      file = _partFile(await baseDirectory(), sessionId, entryId);
    } on PeerException {
      return 0;
    }
    try {
      return await file.length();
    } on FileSystemException {
      return 0;
    }
  }

  // ---------------------------------------------------------------------------
  // ChunkedFileReader
  // ---------------------------------------------------------------------------

  /// Streams `[fromOffset, end)` of [path] in slices of at most
  /// [Transfer.chunkSize].
  ///
  /// ## Why an `async*` generator and not `Stream.fromIterable` / `chunkedByChunk`
  ///
  /// The whole point of this signature is backpressure: the transport pipes the
  /// result into the socket, and when the socket stalls, this generator must
  /// *stop reading the disk* rather than queue gigabytes in the heap.
  ///
  /// An `async*` generator gives exactly that for free. Dart only runs the body
  /// up to the next `yield` when the consumer asks for the next event, so the
  /// `readInto` below cannot run until the socket has accepted the previous
  /// chunk. Peak resident memory is one chunk, independent of file size, and
  /// disk reads are throttled by the network for free.
  ///
  /// `package:async`'s `chunkedByChunk` is deliberately *not* used: it is not a
  /// direct dependency, and adding one just for a 10-line loop is not worth it.
  /// Reading through a `RandomAccessFile` rather than `File.openRead` also lets
  /// us (a) start at an arbitrary offset without a separate stream, and (b) use
  /// one preallocated buffer per slice instead of allocating from the OS for
  /// every read.
  ///
  /// Cancellation (a `break` in the consumer, a `cancel()` on the subscription)
  /// unwinds the `finally`, so the file descriptor is always closed.
  @override
  Stream<List<int>> chunkedFileStream(String path, {int? fromOffset}) async* {
    final file = File(path);
    final raf = await file.open();
    try {
      final length = await raf.length();
      var offset = fromOffset ?? 0;
      if (offset < 0) offset = 0;
      if (offset > length) offset = length;

      raf.setPositionSync(offset);
      while (offset < length) {
        final want = math.min(Transfer.chunkSize, length - offset);
        final buffer = Uint8List(want);
        final read = await raf.readInto(buffer, 0, want);
        if (read <= 0) break; // EOF: file shrank underneath us
        // Hand over the exact slice without copying in the common case where
        // the read filled the buffer completely.
        yield read == want ? buffer : Uint8List.sublistView(buffer, 0, read);
        offset += read;
      }
    } finally {
      await raf.close();
    }
  }

  // ---------------------------------------------------------------------------
  // Path sanitisation (the hostile-input boundary)
  // ---------------------------------------------------------------------------

  /// Validates a single path component from a peer.
  ///
  /// Returns the component unchanged when it is safe, throws
  /// [PeerException] with [ApiError.badRequest] otherwise. Callers must use the
  /// *return value*; it exists so future hardening (length caps, truncation)
  /// has one obvious place to live.
  static String sanitiseComponent(String raw, String what) {
    if (raw.isEmpty) {
      throw PeerException(ApiError.badRequest, 'empty $what');
    }
    if (raw.length > _maxComponentLength) {
      throw PeerException(
        ApiError.badRequest,
        '$what is longer than $_maxComponentLength',
      );
    }
    // NUL: harmless to Dart strings, lethal to C-level syscalls on several
    // platforms, where it silently truncates the path.
    if (raw.contains('\u0000')) {
      throw PeerException(ApiError.badRequest, '$what contains NUL');
    }
    // Both separators, unconditionally. On POSIX a backslash is a legal
    // filename character, but accepting it would let a crafted name become a
    // traversal the moment the same tree is synced to Windows or read by a
    // browser build using `/`-flavour splitting.
    if (raw.contains('/') || raw.contains('\\')) {
      throw PeerException(
        ApiError.badRequest,
        '$what contains a path separator',
      );
    }
    // `.` and `..` are the only single components that can move the cursor.
    if (raw == '.' || raw == '..') {
      throw PeerException(
        ApiError.badRequest,
        '$what is a relative path element',
      );
    }
    // A drive letter (`C:`), an NTFS alternate data stream (`file:stream`), or
    // the scheme separator of a URI-like name. None can appear in a name we
    // accept.
    if (raw.contains(':')) {
      throw PeerException(ApiError.badRequest, '$what contains a colon');
    }
    // Control characters would survive sanitisation and produce names that no
    // file manager can display or delete.
    for (final unit in raw.codeUnits) {
      if (unit < 0x20 || unit == 0x7f) {
        throw PeerException(
          ApiError.badRequest,
          '$what contains a control character',
        );
      }
    }
    // Trailing dots/spaces are silently stripped by Windows, which turns
    // `evil.txt.` into `evil.txt` and can collide with an existing file.
    if (raw.endsWith('.') || raw.endsWith(' ')) {
      throw PeerException(
        ApiError.badRequest,
        '$what ends with a dot or space',
      );
    }
    // Windows device names cannot be created on NTFS at all.
    final stem = raw.split('.').first.toLowerCase();
    if (_reservedDeviceNames.contains(stem)) {
      throw PeerException(
        ApiError.badRequest,
        '$what is a reserved device name',
      );
    }
    return raw;
  }

  /// Validates a peer-chosen *session* id. Same rules as a file name, plus the
  /// length cap, because the session id is a directory name on disk.
  static String sanitiseSessionId(String raw) =>
      sanitiseComponent(raw, 'session id');

  /// Validates a peer-chosen display name and returns a non-empty safe value.
  ///
  /// Unlike [sanitiseComponent] this never throws for an *empty* name: an empty
  /// `name` is common and harmless, so it degrades to the entry id. Everything
  /// that could escape is still rejected.
  static String sanitiseDisplayName(String? raw) {
    final candidate = (raw ?? '').trim();
    if (candidate.isEmpty) return 'file';
    try {
      return sanitiseComponent(candidate, 'file name');
    } on PeerException {
      throw PeerException(ApiError.badRequest, 'unsafe file name');
    }
  }

  /// Validates a relative path (folder transfers) and normalises it to `/`.
  ///
  /// Rejects absolute paths (`/x`, `C:\x`, `\\server\x`), `..` elements, NUL,
  /// control characters and reserved device names. Cosmetic redundancy
  /// (`a//b`, a trailing `/`) is collapsed rather than rejected, so a peer that
  /// builds paths with a stray separator still lands somewhere sensible.
  ///
  /// Returns `null` when [raw] is null or empty.
  static String? sanitiseRelPath(String? raw) {
    if (raw == null || raw.isEmpty) return null;
    if (raw.contains('\u0000')) {
      throw PeerException(ApiError.badRequest, 'relPath contains NUL');
    }
    // An absolute relPath is rejected outright rather than quietly made
    // relative: `sanitiseComponent` happily accepts each of its segments, so
    // without this check `/etc/passwd` would become the harmless-looking
    // `etc/passwd`. Rejecting keeps "the peer asked for something impossible"
    // distinguishable from "the peer sent a slightly odd path".
    if (raw.startsWith('/') || raw.startsWith('\\')) {
      throw PeerException(ApiError.badRequest, 'relPath must be relative');
    }
    if (RegExp(r'^[A-Za-z]:').hasMatch(raw)) {
      throw PeerException(ApiError.badRequest, 'relPath must not be absolute');
    }
    // Treat both separators as separators regardless of platform, for the same
    // reason as in sanitiseComponent.
    final parts = raw.split(RegExp(r'[/\\]'));
    final out = <String>[];
    for (final part in parts) {
      if (part.isEmpty) {
        // `a//b` and a trailing `/` are cosmetic; dropping them keeps the
        // destination canonical.
        continue;
      }
      out.add(sanitiseComponent(part, 'relPath element'));
    }
    if (out.isEmpty) return null;
    return out.join('/');
  }

  /// Joins already-sanitised segments with the platform separator.
  static String _childPath(List<String> segments) =>
      segments.join(Platform.pathSeparator);

  /// Splits a path into meaningful segments, discarding empty and `.` ones.
  ///
  /// Deliberately does **not** resolve `..`: a surviving `..` makes the prefix
  /// comparison in [_assertInsideRoot] fail, which is the safe outcome.
  static List<String> _segments(String path) {
    final parts = path.split(RegExp(r'[/\\]'));
    return [
      for (final p in parts)
        if (p.isNotEmpty && p != '.') _fold(p),
    ];
  }

  /// Windows and macOS compare path components case-insensitively; POSIX does
  /// not. Comparing folded forms on Windows only keeps the check strict.
  static String _fold(String segment) =>
      Platform.isWindows ? segment.toLowerCase() : segment;

  /// Throws unless [candidate] is [root] itself or lives beneath it.
  static void _assertInsideRoot(String root, String candidate) {
    final r = _segments(root);
    final c = _segments(candidate);
    if (c.length < r.length) {
      throw PeerException(ApiError.badRequest, 'path escapes the store root');
    }
    for (var i = 0; i < r.length; i++) {
      if (r[i] != c[i]) {
        throw PeerException(ApiError.badRequest, 'path escapes the store root');
      }
    }
  }

  /// Resolves [dir] and every existing ancestor, and refuses if the real
  /// location is outside [root].
  ///
  /// Steps 1-3 of the threat model are lexical and therefore blind to symlinks.
  /// A peer cannot create one, but a previous version of this app (or the user)
  /// could have left `aero-inbox/downloads -> /etc` behind, after which a
  /// perfectly sanitised `relPath` of `passwd` would still write outside the
  /// root. Resolving the real paths is the only check that sees it.
  static Future<void> _assertNoSymlinkEscape(String root, String dir) async {
    // Walk up from the deepest *existing* ancestor. A directory that does not
    // exist yet cannot be a symlink, so resolving it would just throw; its own
    // containment is already guaranteed by the lexical check.
    var current = Directory(dir);
    while (!current.existsSync()) {
      final parent = current.parent.path;
      if (parent == current.path) break;
      current = Directory(parent);
    }
    // The root has to be resolved too, and this is not a theoretical concern:
    // on macOS every temp dir is `/var/... -> /private/var/...`, so comparing a
    // resolved child against an unresolved root fails for every legitimate
    // destination.
    final realRoot = await Directory(root).resolveSymbolicLinks();
    _assertInsideRoot(realRoot, await current.resolveSymbolicLinks());
  }

  // ---------------------------------------------------------------------------
  // Session manifest (sanitised name / relPath, remembered across calls)
  // ---------------------------------------------------------------------------

  /// `<base>/aero-sessions/<sessionId>/<entryId>.part`.
  ///
  /// Throws [PeerException] when either component is unsafe, so a hostile id can
  /// never even reach `File.length`.
  File _partFile(Directory base, String sessionId, String entryId) {
    final sid = sanitiseSessionId(sessionId);
    final eid = sanitiseComponent(entryId, 'entry id');
    final file = File(
      _childPath([base.path, kSessionsDirName, sid, '$eid$kPartSuffix']),
    );
    _assertInsideRoot(base.path, file.path);
    return file;
  }

  Future<void> _rememberEntry(
    String sessionId,
    FileEntry entry, {
    required String name,
    String? relPath,
  }) {
    return _serialiseManifest(() async {
      final base = await baseDirectory();
      final manifest = await _loadManifest(base, sessionId);
      manifest[entry.id] = {
        'name': name,
        'relPath': relPath,
        'size': entry.size,
      };
      await _storeManifest(base, sessionId, manifest);
    });
  }

  Future<Map<String, dynamic>?> _manifestEntry(
    String sessionId,
    String entryId,
  ) {
    return _serialiseManifest(() async {
      final base = await baseDirectory();
      final manifest = await _loadManifest(base, sessionId);
      return (manifest[entryId] as Map?)?.cast<String, dynamic>();
    });
  }

  Future<T> _serialiseManifest<T>(Future<T> Function() body) {
    final completer = Completer<T>();
    final previous = _manifestLock;
    _manifestLock = completer.future.then((_) {}, onError: (_) {});
    previous.whenComplete(() async {
      try {
        completer.complete(await body());
      } catch (e, s) {
        coreLog.warning('manifest update failed', e, s);
        completer.completeError(e, s);
      }
    });
    return completer.future;
  }

  Future<Map<String, dynamic>> _loadManifest(
    Directory base,
    String sessionId,
  ) async {
    final cached = _manifests[sessionId];
    if (cached != null) return cached;
    final file = File(
      _childPath([base.path, kSessionsDirName, sessionId, kManifestFileName]),
    );
    Map<String, dynamic> parsed = {};
    if (await file.exists()) {
      try {
        final decoded = jsonDecode(await file.readAsString());
        if (decoded is Map<String, dynamic>) parsed = decoded;
      } on FormatException catch (e) {
        coreLog.warning('manifest corrupt at ${file.path}: $e');
      } on FileSystemException catch (e) {
        coreLog.warning('manifest unreadable at ${file.path}', e);
      }
    }
    _manifests[sessionId] = parsed;
    return parsed;
  }

  Future<void> _storeManifest(
    Directory base,
    String sessionId,
    Map<String, dynamic> manifest,
  ) async {
    final file = File(
      _childPath([base.path, kSessionsDirName, sessionId, kManifestFileName]),
    );
    try {
      await file.writeAsString(jsonEncode(manifest));
      _manifests[sessionId] = manifest;
    } on FileSystemException catch (e) {
      // Non-fatal: the transfer can still complete, it just cannot honour a
      // hostile-looking name and will fall back to the entry id.
      coreLog.warning('manifest not written at ${file.path}', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Misc helpers
  // ---------------------------------------------------------------------------

  /// Removes a session's staging directory once its last `.part` is gone, so a
  /// cancelled transfer does not leave a directory and a manifest behind for
  /// every session the app has ever run.
  ///
  /// Fire-and-forget: [discard] is called from `cancel` and from a disconnect
  /// cleanup, and neither may be delayed by a directory listing. Errors are
  /// swallowed because leaving a directory behind is harmless and the caller has
  /// no useful way to react.
  /// Parse the free-byte count from `df` (POSIX) or `wmic` (Windows) output.
  ///
  /// POSIX `df -k -P <path>` prints:
  /// ```
  /// Filesystem   1024-blocks      Used Available Capacity Mounted on
  /// /dev/disk1s1 494384795  300000000 190000000      61% /
  /// ```
  /// and the number we want is the **fourth** field of the last line
  /// (Available, in 1024-byte blocks). `-P` guarantees one line per filesystem
  /// even for long device names, which is why it is passed.
  ///
  /// Anything unexpected returns null rather than a guess: a wrong free-space
  /// answer would accept an offer that cannot be stored.
  static int? _parseFreeSpace(String output, {required bool windows}) {
    if (windows) {
      // `wmic ... /value` prints `FreeSpace=123456789`. Take the first numeric
      // value found; the query is already scoped to one drive.
      final match = RegExp(r'FreeSpace=(\d+)').firstMatch(output);
      if (match == null) return null;
      return int.tryParse(match.group(1)!);
    }

    for (final line in output.trim().split('\n').reversed) {
      final fields = line.trim().split(RegExp(r'\s+'));
      // 6 columns in the portable format; the last is the mount point, which can
      // contain spaces but does not affect the fields we read.
      if (fields.length < 4) continue;
      final availableKb = int.tryParse(fields[3]);
      if (availableKb == null) continue;
      // Guard against a partial/garbled parse producing a nonsense carry.
      final bytes = availableKb * 1024;
      return bytes < 0 ? null : bytes;
    }
    return null;
  }

  /// Remove a now-empty staging directory.
  ///
  /// Awaited rather than fire-and-forget: `discard` and `commit` are the points
  /// where a caller has just removed the last staged file, and both a resuming
  /// peer and a test need the directory gone *by the time the call returns*.
  /// Leaving it to a detached future made cancellation observably racy — the
  /// bytes were deleted but the `.part` directory could still be listed a
  /// moment later.
  Future<void> _dropSessionDirIfEmpty(String partPath) async {
    final dir = File(partPath).parent;
    final sessionId = _manifests.keys
        .where((id) => dir.path.endsWith('$id${Platform.pathSeparator}'))
        .firstOrNull;
    try {
      if (!await dir.exists()) return;
      // The manifest is bookkeeping, not a staged file: it must not keep the
      // directory alive.
      final leftovers = await dir.list().where(
            (e) =>
                e.path.split(Platform.pathSeparator).last != kManifestFileName,
          ).isEmpty;
      if (!leftovers) return;
      await dir.delete(recursive: true);
      if (sessionId != null) _manifests.remove(sessionId);
      coreLog.fine('cleanup: removed the empty staging dir ${dir.path}');
    } on FileSystemException {
      // Leaving an empty staging directory behind is harmless.
    }
  }

}
