// Tests for LocalFileStore — the hostile-input boundary of the whole app.
//
// The traversal cases are the point of this file. Every one of them asserts
// twice: that the operation *failed or was neutralised*, and that nothing
// appeared outside the store root. A sanitiser that only half works still
// passes a "did it throw?" check if the second assertion is missing.

import 'dart:io';
import 'dart:typed_data';

import 'package:aero/core/constants.dart';
import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:aero/core/transfer/local_file_store.dart';
import 'package:aero/core/transfer/receive_destination.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory temp;

  setUp(() {
    temp = Directory.systemTemp.createTempSync('aero_store_test');
  });

  tearDown(() {
    if (temp.existsSync()) temp.deleteSync(recursive: true);
  });

  // A temp destination, not the real Downloads folder: these tests must not
  // write to the developer's disk, and the assertions below need a fixed root.
  LocalFileStore newStore() => LocalFileStore(
        baseDirectory: temp,
        destination: DownloadsDestination(root: Directory('${temp.path}/downloads')),
      );

  /// Every file under [root], as paths relative to it. Used to prove nothing
  /// escaped and to inspect the resulting layout.
  List<String> tree(Directory root) {
    if (!root.existsSync()) return const [];
    final out = <String>[];
    for (final entity in root.listSync(recursive: true)) {
      final rel = entity.path
          .substring(root.path.length)
          .replaceAll(Platform.pathSeparator, '/');
      out.add(rel.startsWith('/') ? rel.substring(1) : rel);
    }
    out.sort();
    return out;
  }

  FileEntry entry(
    String id, {
    String name = 'file.bin',
    int size = 32,
    String? relPath,
    String? sha256,
  }) => FileEntry(
    id: id,
    name: name,
    size: size,
    relPath: relPath,
    sha256: sha256,
  );

  Future<void> writeTo(String path, List<int> bytes) async {
    final file = File(path);
    await file.parent.create(recursive: true);
    await file.writeAsBytes(bytes);
  }

  group('stage + commit round trip', () {
    test('commits byte-identical content', () async {
      final store = newStore();
      final payload = Uint8List.fromList(
        List<int>.generate(4096, (i) => (i * 7 + 13) % 256),
      );

      final staged = await store.stage(
        entry('e1', name: 'payload.bin', size: payload.length),
        's1',
      );
      await writeTo(staged.path, payload);

      final finalPath = await store.commit(staged, 's1');
      final committed = await File(finalPath).readAsBytes();

      expect(committed, equals(payload));
      expect(committed.length, payload.length);
    });

    test('final path is absolute and inside the inbox', () async {
      final store = newStore();
      final staged = await store.stage(
        entry('e1', name: 'a.bin', size: 3),
        's1',
      );
      await writeTo(staged.path, [1, 2, 3]);

      final finalPath = await store.commit(staged, 's1');
      expect(File(finalPath).isAbsolute, isTrue);
      expect(
        finalPath.startsWith('${temp.path}${Platform.pathSeparator}downloads'),
        isTrue,
        reason: 'committed files must land in the inbox, got $finalPath',
      );
      expect(
        File(staged.path).existsSync(),
        isFalse,
        reason: 'the staged .part is moved, not copied',
      );
    });

    test('zero-byte file round trips', () async {
      final store = newStore();
      final staged = await store.stage(
        entry('zero', name: 'empty', size: 0),
        's1',
      );

      expect(File(staged.path).existsSync(), isTrue);
      final finalPath = await store.commit(staged, 's1');
      expect(await File(finalPath).length(), 0);
    });

    test('never overwrites an existing inbox file', () async {
      final store = newStore();
      final first = await store.stage(
        entry('e1', name: 'dup.bin', size: 3),
        's1',
      );
      await writeTo(first.path, [1, 1, 1]);
      final firstPath = await store.commit(first, 's1');

      final second = await store.stage(
        entry('e2', name: 'dup.bin', size: 3),
        's1',
      );
      await writeTo(second.path, [2, 2, 2]);
      final secondPath = await store.commit(second, 's1');

      expect(firstPath, isNot(secondPath));
      expect(await File(firstPath).readAsBytes(), [1, 1, 1]);
      expect(await File(secondPath).readAsBytes(), [2, 2, 2]);
    });
  });

  group('preallocation', () {
    test('staged file has the full length immediately after stage', () async {
      final store = newStore();
      const size = 1 << 20; // 1 MiB
      final staged = await store.stage(entry('big', size: size), 's1');

      // The whole point: ftruncate up-front so the filesystem lays out extents
      // once instead of growing the file block by block as bytes arrive.
      expect(File(staged.path).lengthSync(), size);
      expect(await File(staged.path).readAsBytes(), everyElement(0));
    });

    test('zero size still creates the file', () async {
      final store = newStore();
      final staged = await store.stage(entry('z', size: 0), 's1');
      expect(File(staged.path).existsSync(), isTrue);
      expect(File(staged.path).lengthSync(), 0);
    });

    test('re-staging does not resize or truncate an existing .part', () async {
      // This is what makes resume possible: a second offer for the same
      // (session, entry) must leave the received bytes alone.
      final store = newStore();
      final first = await store.stage(entry('r', size: 1024), 's1');
      await writeTo(first.path, Uint8List.fromList(List.filled(500, 0xAB)));

      final second = await store.stage(entry('r', size: 1024), 's1');

      expect(second.path, first.path);
      expect(
        File(second.path).lengthSync(),
        500,
        reason: 'resume must not be destroyed by re-staging',
      );
      final bytes = await File(second.path).readAsBytes();
      expect(bytes.length, 500);
      expect(bytes.every((b) => b == 0xAB), isTrue);
    });

    test('a smaller declared size resets a stale larger .part', () async {
      final store = newStore();
      final first = await store.stage(entry('s', size: 4096), 's1');
      await writeTo(first.path, Uint8List.fromList(List.filled(4096, 0x01)));

      // The peer re-offers the same id with a different size. Keeping 4096 bytes
      // of a "4000 byte" file would make every length check lie.
      final second = await store.stage(entry('s', size: 100), 's1');
      expect(File(second.path).lengthSync(), 100);
    });
  });

  group('discard', () {
    test('deletes the staged file', () async {
      final store = newStore();
      final staged = await store.stage(entry('d', size: 64), 's1');
      expect(File(staged.path).existsSync(), isTrue);

      await store.discard(staged);
      expect(File(staged.path).existsSync(), isFalse);
    });

    test('ignores a missing file', () async {
      final store = newStore();
      final staged = await store.stage(entry('d', size: 8), 's1');
      await store.discard(staged);

      // Second discard must not throw: `cancel` can race a disconnect cleanup.
      await expectLater(store.discard(staged), completes);
    });

    test('removes the session directory once it is empty', () async {
      final store = newStore();
      final staged = await store.stage(entry('d', size: 8), 's1');
      await store.discard(staged);

      final sessions = Directory(
        '${temp.path}${Platform.pathSeparator}aero-sessions',
      );
      // The manifest sidecar may briefly remain; drain the async cleanup.
      await Future<void>.delayed(const Duration(milliseconds: 20));
      final leftover = tree(sessions).where((p) => p.endsWith('.part'));
      expect(leftover, isEmpty);
    });
  });

  group('existingBytes', () {
    test('is 0 before staging and N after a partial write', () async {
      final store = newStore();
      expect(await store.existingBytes('s1', 'ghost'), 0);

      final staged = await store.stage(entry('p', size: 8192), 's1');
      // Preallocated, so the raw file length is the full size already...
      expect(await store.existingBytes('s1', 'p'), 8192);

      // ...but the protocol's resume oracle is the *received* count, which the
      // caller maintains by truncating to it (see AeroPeerApi.onDisconnect).
      await writeTo(staged.path, Uint8List.fromList(List.filled(1000, 0)));
      expect(await store.existingBytes('s1', 'p'), 1000);
      expect(await store.existingBytes('s1', 'other'), 0);
    });

    test('returns 0 for a hostile entry id rather than throwing', () async {
      final store = newStore();
      expect(await store.existingBytes('s1', '../escape'), 0);
      expect(await store.existingBytes('s1', 'a/../../b'), 0);
    });
  });

  group('path traversal defence', () {
    test('rejects a name containing ..', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e1', name: '../../evil'), 's1'),
        throwsA(isA<PeerException>()),
      );
      expect(tree(temp).where((p) => p.contains('evil')), isEmpty);
    });

    test('rejects an absolute name', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e2', name: '/etc/passwd'), 's1'),
        throwsA(isA<PeerException>()),
      );
      expect(
        File('/etc/passwd').existsSync(),
        isTrue,
        reason: 'sanity: the real file must still be there',
      );
    });

    test('rejects a relPath that climbs out', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e3', relPath: 'a/../../b'), 's1'),
        throwsA(isA<PeerException>()),
      );
    });

    test('rejects a name containing NUL', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e4', name: 'evil\u0000.txt'), 's1'),
        throwsA(isA<PeerException>()),
      );
    });

    test('rejects a relPath containing NUL', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e5', relPath: 'dir\u0000/file.txt'), 's1'),
        throwsA(isA<PeerException>()),
      );
    });

    test('rejects a hostile session id', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('e6'), '../outside'),
        throwsA(isA<PeerException>()),
      );
    });

    test('rejects a hostile entry id', () async {
      final store = newStore();
      await expectLater(
        store.stage(entry('../../escape', size: 1), 's1'),
        throwsA(isA<PeerException>()),
      );
      expect(File('${temp.path}/../../escape.part').existsSync(), isFalse);
    });

    test('never escapes the base directory, whatever it is handed', () async {
      // The catch-all: whatever combination of name, relPath, session id and
      // entry id a hostile peer produces, the only things that appear on disk
      // must be under [temp].
      final store = newStore();
      final attacks =
          <({String name, String? relPath, String session, String id})>[
            (
              name: '../../../../etc/passwd',
              relPath: null,
              session: 's',
              id: 'a',
            ),
            (name: '/etc/passwd', relPath: null, session: 's', id: 'b'),
            (name: 'ok.txt', relPath: '../../../../tmp', session: 's', id: 'c'),
            (name: 'ok.txt', relPath: '/absolute', session: 's', id: 'd'),
            (name: 'ok.txt', relPath: null, session: '../s2', id: 'e'),
            (name: 'ok.txt', relPath: null, session: 's', id: '../../f'),
            (name: 'a/b', relPath: null, session: 's', id: 'g'),
            (name: 'ok.txt', relPath: 'x/../../y', session: '/tmp', id: 'h'),
            (name: 'C:\\Windows\\evil', relPath: null, session: 's', id: 'i'),
            (name: 'ok.txt', relPath: 'C:\\evil', session: 's', id: 'j'),
            (name: '   ', relPath: null, session: 's', id: 'k'),
            (name: '.', relPath: '.', session: 's', id: 'l'),
            (name: '..', relPath: '..', session: '.', id: 'm'),
            (name: 'trailing.', relPath: null, session: 's', id: 'n'),
            (name: 'CON', relPath: null, session: 's', id: 'o'),
            (name: 'ok.txt', relPath: 'nested:stream', session: 's', id: 'p'),
          ];

      for (final attack in attacks) {
        try {
          final staged = await store.stage(
            FileEntry(
              id: attack.id,
              name: attack.name,
              size: 4,
              relPath: attack.relPath,
            ),
            attack.session,
          );
          // Anything that *did* stage must be inside the root and then commit
          // inside the inbox — the containment assertion covers both legs.
          expect(
            File(staged.path).absolute.path.startsWith(temp.absolute.path),
            isTrue,
            reason: 'staged path escaped: ${staged.path}',
          );
          await writeTo(staged.path, [1, 2, 3, 4]);
          final finalPath = await store.commit(staged, attack.session);
          expect(
            File(finalPath).absolute.path.startsWith(temp.absolute.path),
            isTrue,
            reason: 'committed path escaped: $finalPath',
          );
        } on PeerException {
          // The expected outcome for most of these.
        }
      }

      // Nothing was created next to the temp dir.
      final parent = temp.parent;
      final siblings = parent
          .listSync()
          .map((e) => e.path.split(Platform.pathSeparator).last)
          .toSet();
      expect(siblings.contains('escape.part'), isFalse);
      expect(siblings.contains('escape'), isFalse);
      expect(siblings.contains('outside'), isFalse);
    });

    test('sanitiseComponent rejects every documented hazard', () {
      final hazards = <String>[
        '',
        '.',
        '..',
        '../evil',
        'a/b',
        r'a\b',
        '\u0000name',
        'trailing.',
        'trailing ',
        'C:evil',
        'stream:ads',
        'CON',
        'nul.txt',
        'PRN',
        // Long enough to exceed a component limit on every target.
        'x' * 300,
      ];
      for (final hazard in hazards) {
        // `expect(closure, throwsA(...))` is unreliable here: the closure runs
        // while the matcher is still being constructed, so a *passing* call is
        // reported as "Actual: <Closure>" instead of as a failure. Calling it by
        // hand makes the assertion unambiguous.
        Object? thrown;
        var rejected = false;
        try {
          LocalFileStore.sanitiseComponent(hazard, 'test component');
        } catch (e) {
          thrown = e;
          rejected = true;
        }
        expect(
          rejected,
          isTrue,
          reason: 'must reject ${hazard.replaceAll('\u0000', '<NUL>')}',
        );
        expect(thrown, isA<PeerException>());
      }
    });

    test('sanitiseComponent accepts ordinary names', () {
      for (final ok in [
        'file.txt',
        'a b c',
        'ünïcödé.png',
        '..hidden',
        'x..y',
      ]) {
        expect(LocalFileStore.sanitiseComponent(ok, 'test component'), ok);
      }
    });

    test('sanitiseRelPath normalises and rejects', () {
      expect(LocalFileStore.sanitiseRelPath('a/b/c.txt'), 'a/b/c.txt');
      expect(LocalFileStore.sanitiseRelPath('a//b.txt'), 'a/b.txt');
      expect(LocalFileStore.sanitiseRelPath('a\\b.txt'), 'a/b.txt');
      expect(LocalFileStore.sanitiseRelPath(''), isNull);
      expect(LocalFileStore.sanitiseRelPath(null), isNull);

      for (final bad in [
        '../x',
        'a/../../b',
        '/abs',
        'a/../..',
        'a/./../b',
        r'C:\abs',
        r'\\server\share',
      ]) {
        Object? thrown;
        var rejected = false;
        try {
          LocalFileStore.sanitiseRelPath(bad);
        } catch (e) {
          thrown = e;
          rejected = true;
        }
        expect(rejected, isTrue, reason: 'must reject $bad');
        expect(thrown, isA<PeerException>());
      }
    });
  });

  group('relPath nesting', () {
    test('creates intermediate directories and stays in the inbox', () async {
      final store = newStore();
      final staged = await store.stage(
        entry('n', name: 'leaf.txt', relPath: 'photos/2026/june', size: 5),
        's1',
      );
      await writeTo(staged.path, [9, 9, 9, 9, 9]);

      // relPath is the *directory*; the file keeps its own name inside it.
      final finalPath = await store.commit(staged, 's1');
      final inbox = '${temp.path}${Platform.pathSeparator}downloads';

      expect(
        File(finalPath).absolute.path,
        startsWith('$inbox${Platform.pathSeparator}'),
      );
      expect(finalPath.endsWith('leaf.txt'), isTrue);
      expect(
        finalPath,
        endsWith(
          'photos${Platform.pathSeparator}2026'
          '${Platform.pathSeparator}june${Platform.pathSeparator}leaf.txt',
        ),
      );
      expect(await File(finalPath).readAsBytes(), [9, 9, 9, 9, 9]);
    });

    test('a deep tree does not escape via many .. segments', () async {
      final store = newStore();
      // 200 levels of traversal: enough to reach anywhere if even one check
      // were missing.
      final evil = '../' * 200;
      await expectLater(
        store.stage(entry('deep', relPath: '${evil}escaped.txt'), 's1'),
        throwsA(isA<PeerException>()),
      );
      expect(File('${temp.parent.path}/escaped.txt').existsSync(), isFalse);
    });
  });

  group('chunkedFileStream', () {
    test('yields the whole file in Transfer.chunkSize slices', () async {
      final store = newStore();
      final path = '${temp.path}/source.bin';
      final payload = Uint8List.fromList(
        List<int>.generate(1000, (i) => i % 256),
      );
      await writeTo(path, payload);

      final chunks = await store.chunkedFileStream(path).toList();
      expect(chunks.length, 1, reason: '1000 bytes fits in one slice');
      expect(chunks.single, equals(payload));
    });

    test('fromOffset returns exactly the tail', () async {
      final store = newStore();
      final path = '${temp.path}/tail.bin';
      final payload = Uint8List.fromList(
        List<int>.generate(1000, (i) => i % 256),
      );
      await writeTo(path, payload);

      final chunks = await store
          .chunkedFileStream(path, fromOffset: 250)
          .toList();
      final got = chunks.expand((c) => c).toList();

      expect(got, equals(payload.sublist(250)));
      expect(got.length, 750);
    });

    test('fromOffset beyond EOF yields nothing', () async {
      final store = newStore();
      final path = '${temp.path}/small.bin';
      await writeTo(path, [1, 2, 3]);

      expect(
        await store.chunkedFileStream(path, fromOffset: 99).toList(),
        isEmpty,
      );
      expect(
        await store.chunkedFileStream(path, fromOffset: 3).toList(),
        isEmpty,
      );
    });

    test('negative fromOffset is clamped to zero', () async {
      final store = newStore();
      final path = '${temp.path}/neg.bin';
      await writeTo(path, [1, 2, 3, 4]);

      final got = (await store.chunkedFileStream(path, fromOffset: -5).toList())
          .expand((c) => c)
          .toList();
      expect(got, [1, 2, 3, 4]);
    });

    test('splits a large file into multiple slices and reassembles exactly', () async {
      final store = newStore();
      final path = '${temp.path}/big.bin';
      // 1.5x the chunk size, so there are exactly two slices plus a remainder.
      final size = Transfer.chunkSize + 1234;
      final payload = Uint8List.fromList(
        List<int>.generate(size, (i) => (i * 31) % 256),
      );
      await writeTo(path, payload);

      final chunks = <List<int>>[];
      await for (final chunk in store.chunkedFileStream(path)) {
        expect(chunk.length, lessThanOrEqualTo(Transfer.chunkSize));
        chunks.add(chunk);
      }

      expect(chunks.length, 2);
      expect(chunks.first.length, Transfer.chunkSize);
      expect(chunks.last.length, 1234);
      expect(chunks.expand((c) => c).toList(), equals(payload));
    });

    test('yields a short final slice rather than a padded one', () async {
      // The last read of a file whose length is not a multiple of the chunk size
      // must hand back exactly the remaining bytes. Padding it out would send
      // garbage and every digest check would fail on a file that was fine.
      final store = newStore();
      final path = '${temp.path}/ragged.bin';
      final size = Transfer.chunkSize + 77;
      await writeTo(path, List<int>.filled(size, 7));

      final got = <int>[];
      final lengths = <int>[];
      await for (final chunk in store.chunkedFileStream(path)) {
        lengths.add(chunk.length);
        got.addAll(chunk);
      }

      expect(lengths, [Transfer.chunkSize, 77]);
      expect(got.length, size);
      expect(got.every((b) => b == 7), isTrue);
    });

    test('cancelling the subscription releases the file handle', () async {
      // A leaked descriptor here would show up as an EMFILE much later, in
      // production, on a long-running app. Asserting it is cheap.
      final store = newStore();
      final path = '${temp.path}/cancel.bin';
      await writeTo(path, List<int>.filled(Transfer.chunkSize * 3, 2));

      final stream = store.chunkedFileStream(path);
      final first = await stream.first;
      expect(first.length, Transfer.chunkSize);

      // The generator's `finally` runs on cancel; deleting proves no handle is
      // still pinned (advisory on POSIX, but a real failure on Windows).
      await Future<void>.delayed(const Duration(milliseconds: 10));
      File(path).deleteSync();
      expect(File(path).existsSync(), isFalse);
    });
  });

  group('freeSpace', () {
    test('reports a real value on desktop, or null where it cannot be known', () async {
      final store = newStore();
      final free = await store.freeSpace();
      if (Platform.isAndroid || Platform.isIOS) {
        // Shelling out is unavailable, and a guess would be worse than nothing.
        expect(free, isNull);
      } else {
        // On desktop `df` answers reliably; the volume holding the temp
        // directory must have *some* free space.
        expect(free, isNotNull);
        expect(free, greaterThan(0));
      }
    });

    test('parses POSIX df output, taking the Available column', () {
      const output = 'Filesystem   1024-blocks      Used Available Capacity Mounted on\n'
          '/dev/disk1s1   494384795 300000000 190000000      61% /\n';
      // 190000000 KiB * 1024 = the Available column, not Used or Blocks.
      expect(
        LocalFileStore.parseFreeSpaceForTest(output),
        190000000 * 1024,
      );
    });

    test('parses Windows wmic output', () {
      expect(
        LocalFileStore.parseFreeSpaceForTest(
          'FreeSpace=123456789\r\n',
          windows: true,
        ),
        123456789,
      );
    });

    test('returns null on unparseable output rather than guessing', () {
      // A guess would accept an offer that cannot be stored.
      expect(LocalFileStore.parseFreeSpaceForTest('no numbers here'), isNull);
      expect(LocalFileStore.parseFreeSpaceForTest(''), isNull);
      expect(LocalFileStore.parseFreeSpaceForTest('FreeSpace=abc', windows: true), isNull);
    });

    test('ignores a truncated df line with too few columns', () {
      // `-P` prevents wrapped lines, but a truncated capture must not be read as
      // a huge free-space value.
      expect(LocalFileStore.parseFreeSpaceForTest('Filesystem 1024-blocks'), isNull);
    });
  });

  group('layout', () {
    test('sessions and inbox are separate top-level directories', () async {
      final store = newStore();
      final staged = await store.stage(
        entry('l', name: 'x.bin', size: 2),
        'sess',
      );
      await writeTo(staged.path, [1, 2]);
      await store.commit(staged, 'sess');

      final layout = tree(temp);
      // `commit` publishes the file and then removes the now-empty session
      // directory, so after a successful commit only the destination remains.
      expect(
        layout.any((p) => p.startsWith('aero-sessions/')),
        isFalse,
        reason: 'a committed file must not leave its staging directory behind',
      );
      expect(layout.any((p) => p.startsWith('downloads/')), isTrue);
      expect(
        layout.where((p) => p.endsWith('.part')),
        isEmpty,
        reason: 'no .part may survive a successful commit',
      );
    });
  });
}
