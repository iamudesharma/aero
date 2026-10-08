/// Where received files are delivered so the *user* can find them.
///
/// The app's own support directory is the wrong place for a finished transfer:
/// on Android it is `/data/user/0/<pkg>/files/`, which no file manager, gallery
/// or Files app can see, and on macOS it is buried inside
/// `~/Library/Containers/<bundle-id>/…`. A file that arrives but cannot be
/// found is indistinguishable from a file that never arrived, so delivery is a
/// distinct, platform-specific step rather than "move it next to the staging
/// area".
library;

import 'dart:io';

import 'package:file_saver/file_saver.dart';
import 'package:path/path.dart' as p;

import '../logging.dart';

/// Publishes a completed file somewhere the user can reach it.
abstract class ReceiveDestination {
  /// Short description for diagnostics, e.g. `Downloads/Aero`.
  String get label;

  /// Where the user should look, phrased for a person.
  String get userHint;

  /// Move or copy [stagedPath] into the destination under [name].
  ///
  /// [relPath] recreates a folder structure and may be null for a root-level
  /// file. Returns a human-readable location (an absolute path, or an Android
  /// `content://` URI).
  ///
  /// Implementations must not throw for ordinary failures: a transfer that has
  /// already been verified byte-for-byte must not be reported as failed just
  /// because publishing went wrong. They return the fallback location instead.
  Future<String> publish({
    required String stagedPath,
    required String name,
    String? relPath,
  });
}

/// `~/Downloads/Aero` — macOS, Windows and Linux.
///
/// All three give an ordinary user-writable Downloads directory, and macOS is
/// allowed to write there thanks to
/// `com.apple.security.files.downloads.read-write`.
class DownloadsDestination implements ReceiveDestination {
  DownloadsDestination({required this.root});

  final Directory root;

  @override
  String get label => 'Downloads/Aero';

  @override
  String get userHint => '${root.path}${Platform.pathSeparator}Aero';

  @override
  Future<String> publish({
    required String stagedPath,
    required String name,
    String? relPath,
  }) async {
    final safeName = _safeComponent(name);
    final directory = _subdirectory(root, relPath);
    await directory.create(recursive: true);

    final target = File(p.join(directory.path, _uniqueName(directory, safeName)));

    // A rename within the same volume is atomic and free; a cross-volume move
    // degrades to copy+delete, which is what we want for a large file that is
    // already fully written.
    try {
      await File(stagedPath).rename(target.path);
    } on FileSystemException {
      await File(stagedPath).copy(target.path);
      await File(stagedPath).delete();
    }
    return target.path;
  }
}

/// Android shared Downloads, through MediaStore.
///
/// A plain file path cannot be written under `/sdcard/Download` on Android 10+:
/// scoped storage requires the media store, which is exactly what
/// [`FileSaver.saveToDownloads`] uses. It streams from the staged path, so a
/// multi-gigabyte file is never buffered in memory. No runtime permission is
/// needed on API 29+.
class AndroidMediaStoreDestination implements ReceiveDestination {
  AndroidMediaStoreDestination();

  /// The single folder name MediaStore files are grouped under, shown to the
  /// user as `Downloads/Aero`.
  static const String subfolder = 'Aero';

  /// Remembers the last published location so the UI can say where to look.
  String? lastLocation;

  @override
  String get label => 'Downloads/$subfolder';

  @override
  String get userHint => 'Downloads ▸ $subfolder';

  @override
  Future<String> publish({
    required String stagedPath,
    required String name,
    String? relPath,
  }) async {
    final safeName = _safeComponent(name);
    // MediaStore flattens relative paths, so a nested structure is encoded in
    // the file name rather than the folder. Losing the directory would be
    // worse: two `photo.jpg` from different folders must not collide.
    final flattened = relPath == null || relPath.isEmpty
        ? safeName
        : '${_safeComponent(relPath.replaceAll(RegExp(r'[/\\]+'), '_'))}'
            '_$safeName';

    final dot = flattened.lastIndexOf('.');
    final base = dot > 0 ? flattened.substring(0, dot) : flattened;
    final ext = dot > 0 ? flattened.substring(dot + 1) : '';

    try {
      final saved = await FileSaver.instance.saveToDownloads(
        name: base,
        filePath: stagedPath,
        fileExtension: ext,
        includeExtension: ext.isNotEmpty,
        mimeType: MimeType.custom,
        customMimeType: _mimeTypeFor(ext),
        subfolder: subfolder,
      );
      await _deleteQuietly(stagedPath);
      lastLocation = saved ?? userHint;
      coreLog.info('published $flattened to ${lastLocation ?? userHint}');
      return lastLocation ?? userHint;
    } catch (error, stack) {
      // The bytes are already verified and complete. Report the fallback
      // location rather than failing the transfer.
      coreLog.warning('could not publish $flattened to Downloads', error, stack);
      return userHint;
    }
  }
}

/// Fallback: the app's own support directory.
///
/// Used for iOS (no shared Downloads folder exists) and whenever the preferred
/// destination cannot be resolved. Files here are only reachable through the
/// app itself, which is why [userHint] says so explicitly instead of implying
/// they are in a file manager.
class AppSupportDestination implements ReceiveDestination {
  AppSupportDestination({required this.root});

  final Directory root;

  @override
  String get label => 'app storage (aero-inbox)';

  @override
  String get userHint => 'Inside the app only';

  @override
  Future<String> publish({
    required String stagedPath,
    required String name,
    String? relPath,
  }) async {
    final safeName = _safeComponent(name);
    final directory = _subdirectory(root, relPath);
    await directory.create(recursive: true);
    final target = File(p.join(directory.path, _uniqueName(directory, safeName)));
    try {
      await File(stagedPath).rename(target.path);
    } on FileSystemException {
      await File(stagedPath).copy(target.path);
      await File(stagedPath).delete();
    }
    return target.path;
  }
}

/// Pick the best destination this platform offers.
///
/// [supportDir] is injected so tests do not need a real app-support directory.
ReceiveDestination resolveReceiveDestination({required Directory supportDir}) {
  try {
    if (Platform.isAndroid) return AndroidMediaStoreDestination();
    if (Platform.isIOS) return AppSupportDestination(root: supportDir);
    final downloads = _downloadsDirectory();
    if (downloads != null) {
      return DownloadsDestination(root: Directory(p.join(downloads.path, 'Aero')));
    }
  } catch (error) {
    coreLog.warning('could not resolve a user-visible receive destination', error);
  }
  return AppSupportDestination(root: supportDir);
}

Directory? _downloadsDirectory() {
  // macOS sandboxes the app, so `$HOME` points INSIDE the container:
  //   ~/Library/Containers/<bundle-id>/Data
  // and `$HOME/Downloads` therefore resolves to a directory that Finder never
  // shows. The real user home is the parent of `Library/Containers`.
  //
  // This is not cosmetic: a file written to the container is exactly as
  // invisible as one written to app support, which is the bug this whole layer
  // exists to prevent.
  if (Platform.isMacOS) {
    final realHome = _realMacOsHome();
    if (realHome != null) {
      final downloads = Directory(p.join(realHome.path, 'Downloads'));
      if (downloads.existsSync()) return downloads;
    }
  }

  final home = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (home == null || home.isEmpty) return null;
  final candidate = Directory(p.join(home, 'Downloads'));
  if (!candidate.existsSync()) return null;
  return candidate;
}

/// The user's actual home directory on macOS, escaping the app-container view.
///
/// `NSHomeDirectory()` inside a sandbox returns the container. Two independent
/// signals are used, because `HOME` alone is wrong and the passwd database alone
/// can be stale under network accounts:
///
///  1. strip `/Library/Containers/<bundle>/Data` from `$HOME`;
///  2. otherwise consult `getpwuid`, which returns the real home.
Directory? _realMacOsHome() {
  final home = Platform.environment['HOME'] ?? '';
  const marker = '/Library/Containers/';
  final index = home.indexOf(marker);
  if (index > 0) {
    final candidate = Directory(home.substring(0, index));
    if (candidate.existsSync()) return candidate;
  }

  final fromPasswd = _homeFromPasswd();
  if (fromPasswd != null && fromPasswd.existsSync()) return fromPasswd;

  // `$HOME` may already be the real home when the app is run unsigned from a
  // terminal during development.
  final asIs = Directory(home);
  if (home.isNotEmpty && asIs.existsSync() && !home.contains(marker)) return asIs;
  return null;
}

/// Ask the password database for the real home directory.
Directory? _homeFromPasswd() {
  try {
    final uid = Process.runSync('/usr/bin/id', ['-u']).stdout.toString().trim();
    final out = Process.runSync('/usr/bin/dscl', ['.', '-read', '/Users/$uid', 'NFSHomeDirectory'])
        .stdout
        .toString()
        .trim();
    // Output looks like: "NFSHomeDirectory: /Users/someone"
    final value = out.contains(':') ? out.split(':').last.trim() : out;
    return value.isEmpty ? null : Directory(value);
  } catch (_) {
    return null;
  }
}

Directory _subdirectory(Directory root, String? relPath) {
  if (relPath == null || relPath.isEmpty) return root;
  // Each element is validated individually: a `relPath` that arrived from a
  // peer must not be able to walk out of the destination.
  final parts = relPath
      .split(RegExp(r'[/\\]+'))
      .where((s) => s.isNotEmpty && s != '.' && s != '..')
      .map(_safeComponent)
      .toList();
  return Directory(p.joinAll([root.path, ...parts]));
}

/// Strip anything that would change the meaning of a path.
String _safeComponent(String raw) {
  var s = raw.replaceAll(RegExp(r'[/\\:\x00-\x1f]'), '_').trim();
  s = s.replaceAll(RegExp(r'^\.+'), '_');
  s = s.replaceAll(RegExp(r'[. ]+$'), '');
  if (s.isEmpty) s = 'file';
  if (s.length > 200) {
    final dot = s.lastIndexOf('.');
    final ext = dot > 0 && s.length - dot <= 12 ? s.substring(dot) : '';
    s = '${s.substring(0, 200 - ext.length)}$ext';
  }
  return s;
}

/// Never overwrite: two sends of `photo.jpg` must both survive.
String _uniqueName(Directory directory, String name) {
  if (!File(p.join(directory.path, name)).existsSync()) return name;
  final dot = name.lastIndexOf('.');
  final base = dot > 0 ? name.substring(0, dot) : name;
  final ext = dot > 0 ? name.substring(dot) : '';
  for (var i = 2; i < 10000; i++) {
    final candidate = '$base ($i)$ext';
    if (!File(p.join(directory.path, candidate)).existsSync()) return candidate;
  }
  return '$base-${DateTime.now().millisecondsSinceEpoch}$ext';
}

Future<void> _deleteQuietly(String path) async {
  try {
    final f = File(path);
    if (f.existsSync()) await f.delete();
  } catch (error) {
    coreLog.fine('could not delete staged file $path', error);
  }
}

String _mimeTypeFor(String extension) {
  switch (extension.toLowerCase()) {
    case 'png':
      return 'image/png';
    case 'jpg':
    case 'jpeg':
      return 'image/jpeg';
    case 'gif':
      return 'image/gif';
    case 'webp':
      return 'image/webp';
    case 'heic':
      return 'image/heic';
    case 'mp4':
      return 'video/mp4';
    case 'mov':
      return 'video/quicktime';
    case 'mkv':
      return 'video/x-matroska';
    case 'mp3':
      return 'audio/mpeg';
    case 'm4a':
      return 'audio/mp4';
    case 'wav':
      return 'audio/wav';
    case 'pdf':
      return 'application/pdf';
    case 'zip':
      return 'application/zip';
    case 'apk':
      return 'application/vnd.android.package-archive';
    case 'txt':
      return 'text/plain';
    default:
      return 'application/octet-stream';
  }
}
