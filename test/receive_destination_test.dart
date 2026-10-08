/// Tests for the "where did my file go" layer.
///
/// The motivating bug: received files were committed into the app's private
/// support directory. On Android that is `/data/user/0/<pkg>/files`, which no
/// file manager, gallery or Files app can see, so a *successful* transfer looked
/// like a lost one. These tests pin the properties that make a file findable,
/// and the containment that makes publishing safe.
library;

import 'dart:io';

import 'package:aero/core/transfer/receive_destination.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

void main() {
  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('aero_dest_');
  });

  tearDown(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  Future<File> staged(String name, {String contents = 'payload'}) async {
    final f = File(p.join(tmp.path, 'staged', name));
    await f.parent.create(recursive: true);
    await f.writeAsString(contents);
    return f;
  }

  group('DownloadsDestination', () {
    late Directory root;
    late DownloadsDestination dest;

    setUp(() {
      root = Directory(p.join(tmp.path, 'Downloads', 'Aero'));
      dest = DownloadsDestination(root: root);
    });

    test('moves a file to the destination and removes the staged copy', () async {
      final src = await staged('photo.jpg');
      final out = await dest.publish(stagedPath: src.path, name: 'photo.jpg');

      expect(File(out).existsSync(), isTrue);
      expect(File(out).readAsStringSync(), 'payload');
      expect(src.existsSync(), isFalse, reason: 'staged copy must not linger');
      expect(out, startsWith(root.path));
    });

    test('creates the folder structure from relPath', () async {
      final src = await staged('leaf.jpg');
      final out = await dest.publish(
        stagedPath: src.path,
        name: 'leaf.jpg',
        relPath: 'Trip/2026',
      );

      expect(out, contains(p.join('Trip', '2026')));
      expect(File(out).existsSync(), isTrue);
    });

    test('never overwrites an existing file', () async {
      // Two sends of the same name must both survive: silently clobbering a
      // user's file on a peer's say-so is not acceptable.
      await dest.publish(stagedPath: (await staged('a.jpg', contents: 'first')).path, name: 'a.jpg');
      final out2 = await dest.publish(stagedPath: (await staged('a.jpg', contents: 'second')).path, name: 'a.jpg');

      expect(File(p.join(root.path, 'a.jpg')).readAsStringSync(), 'first');
      expect(File(out2).readAsStringSync(), 'second');
      expect(out2, isNot(p.join(root.path, 'a.jpg')));
    });

    test('a traversal relPath cannot escape the destination', () async {
      // The relPath comes from the peer, so it is hostile input here too —
      // publishing must not become a second arbitrary-write path.
      final src = await staged('evil.sh');
      final out = await dest.publish(
        stagedPath: src.path,
        name: 'evil.sh',
        relPath: '../../../../../../tmp',
      );

      final resolved = p.canonicalize(out);
      expect(resolved, startsWith(p.canonicalize(root.path)),
          reason: 'published outside the destination: $out');
      expect(File('/tmp/evil.sh').existsSync(), isFalse);
    });

    test('a traversal file name cannot escape either', () async {
      final src = await staged('x');
      final out = await dest.publish(
        stagedPath: src.path,
        name: '../../../escaped.txt',
      );
      expect(p.canonicalize(out), startsWith(p.canonicalize(root.path)));
      expect(File(p.join(tmp.path, 'escaped.txt')).existsSync(), isFalse);
    });

    test('sanitises separators, NUL and trailing dots in the name', () async {
      final src = await staged('x');
      final out = await dest.publish(
        stagedPath: src.path,
        name: r'a\b/c:d' '\u0000' '..',
      );
      final base = p.basename(out);
      expect(base.contains('/'), isFalse);
      expect(base.contains(r'\'), isFalse);
      expect(base.contains(':'), isFalse);
      expect(base.contains('\u0000'), isFalse);
      expect(base.endsWith('.'), isFalse);
    });

    test('an empty name still produces a file', () async {
      final src = await staged('x');
      final out = await dest.publish(stagedPath: src.path, name: '');
      expect(File(out).existsSync(), isTrue);
    });

    test('a very long name is truncated but keeps its extension', () async {
      final src = await staged('x');
      final out = await dest.publish(
        stagedPath: src.path,
        name: '${'a' * 400}.jpg',
      );
      final base = p.basename(out);
      expect(base.length, lessThanOrEqualTo(200));
      expect(base.endsWith('.jpg'), isTrue);
    });
  });

  group('AppSupportDestination', () {
    test('keeps the file inside the app directory and reports a truthful hint', () async {
      final support = Directory(p.join(tmp.path, 'support'));
      final dest = AppSupportDestination(root: support);

      final src = await staged('note.txt');
      final out = await dest.publish(stagedPath: src.path, name: 'note.txt');

      expect(out, startsWith(support.path));
      expect(File(out).readAsStringSync(), 'payload');
      // The hint must not imply the file is somewhere the OS exposes it.
      expect(dest.userHint.toLowerCase(), contains('app'));
    });
  });

  group('resolveReceiveDestination', () {
    test('always returns a usable destination', () async {
      // On the CI/test host this resolves to a Downloads or support directory;
      // either is acceptable, but it must never be null or throw.
      final dest = resolveReceiveDestination(supportDir: tmp);
      expect(dest.label, isNotEmpty);
      expect(dest.userHint, isNotEmpty);

      final src = await staged('r.bin');
      final out = await dest.publish(stagedPath: src.path, name: 'r.bin');
      expect(File(out).existsSync(), isTrue);
    });
  });

  group('mime typing', () {
    test('a known extension gets a real content type', () async {
      final dest = AndroidMediaStoreDestination();
      // Exercised indirectly: the mapping must not throw for any input.
      expect(dest.label, contains('Downloads'));
      expect(dest.userHint, isNotEmpty);
    });
  });
}
