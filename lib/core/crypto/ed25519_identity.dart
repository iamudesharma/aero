/// The device's long-lived Ed25519 identity, persisted across launches.
///
/// Trust-on-first-use needs to recognise a device the user has paired with
/// before, which means the key pair has to survive app restarts — so unlike the
/// per-session certificates in `ephemeral_certificate.dart`, this one is
/// written to disk exactly once.
///
/// ## Storage
///
/// `<app support dir>/identity.json`:
/// ```json
/// {"deviceId":"<32 hex chars>","publicKey":"<base64 of 32 raw bytes>",
///  "privateKeyB64":"<base64 of 32-byte seed>"}
/// ```
///
/// The file is written **atomically** (write `identity.json.tmp`, then
/// `rename`). A crash or a full disk partway through a plain `writeAsString`
/// would leave a truncated JSON file, and the recovery path for that is to
/// generate a *new identity* — which silently invalidates every trust record
/// the user has. `rename` within a directory is atomic on APFS, NTFS, ext4 and
/// friends, so the on-disk file is always either the old one or the new one.
///
/// `path_provider` cannot be called from a unit test without a platform
/// channel, so [load] takes an optional directory override.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:path_provider/path_provider.dart';

import '../contracts.dart';
import '../logging.dart';
import 'ephemeral_certificate.dart';

/// Ed25519 key pair plus a stable random device id.
class Ed25519Identity implements DeviceIdentity {
  Ed25519Identity._({
    required SimpleKeyPair keyPair,
    required Uint8List publicKey,
    required String deviceId,
    required Directory directory,
    required Ed25519 algorithm,
  })  : _keyPair = keyPair,
        _publicKey = publicKey,
        _deviceId = deviceId,
        _directory = directory,
        _ed25519 = algorithm;

  // ignore_for_file: prefer_initializing_formals
  // The constructor above takes named parameters without the leading
  // underscore because the fields are private; the lint's suggested
  // `this._field` form cannot be used with named parameters in Dart.

  /// File name inside [directory]. Exposed for tests and diagnostics.
  static const String fileName = 'identity.json';

  static const int _deviceIdBytes = 16; // 128 bits, per DeviceIdentity.deviceId
  static const int _nonceBytes = 16;
  static const int _signatureBytes = 64; // RFC 8032 Ed25519

  final SimpleKeyPair _keyPair;
  final Uint8List _publicKey;
  final String _deviceId;
  final Directory _directory;
  final Ed25519 _ed25519;

  /// Loads the persisted identity, generating and persisting one on first run.
  ///
  /// Pass [directory] to override the location (tests, portable mode). When
  /// omitted, the platform app-support directory is used — the right place for
  /// state that should survive an app upgrade but is not user documents and does
  /// not belong in iCloud/iCloud Drive.
  static Future<Ed25519Identity> load({Directory? directory}) async {
    final dir = directory ?? await getApplicationSupportDirectory();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    return _loadOrCreate(dir);
  }

  static Future<Ed25519Identity> _loadOrCreate(Directory dir) async {
    final file = File('${dir.path}${Platform.pathSeparator}$fileName');
    if (await file.exists()) {
      final parsed = await _tryParse(file);
      if (parsed != null) return parsed;
      // Unreachable in practice because of the atomic write, but a hand-edited
      // or partially-synced file can still be junk. Regenerating is the safe
      // choice: it costs the user a re-pair, whereas trusting a half-read key
      // would cost them their identity. Peers that knew the old id will report
      // TrustState.identityConflict, which is exactly the intended signal.
      coreLog.warning(
        'identity.json at ${file.path} is unreadable; generating a new identity',
      );
    }
    return _create(dir, file);
  }

  static Future<Ed25519Identity?> _tryParse(File file) async {
    try {
      final json = jsonDecode(file.readAsStringSync());
      if (json is! Map<String, dynamic>) return null;
      final deviceId = json['deviceId'];
      final publicKeyB64 = json['publicKey'];
      final privateKeyB64 = json['privateKeyB64'];
      if (deviceId is! String ||
          publicKeyB64 is! String ||
          privateKeyB64 is! String) {
        return null;
      }
      final seed = base64Decode(privateKeyB64);
      final storedPublicKey = base64Decode(publicKeyB64);
      if (seed.length != 32 || storedPublicKey.length != 32) return null;
      if (!_isHex(deviceId, _deviceIdBytes * 2)) return null;

      final ed25519 = Ed25519();
      final keyPair = await ed25519.newKeyPairFromSeed(seed);

      // Re-derive the public key from the seed rather than trusting the stored
      // one: a tampered `publicKey` field must not produce an object that signs
      // with a key it does not hold, nor one that advertises a key whose
      // signatures will never verify.
      final publicKey = rawEd25519PublicKey(await keyPair.extractPublicKey());
      if (!_sameBytes(publicKey, storedPublicKey)) {
        coreLog.warning(
          'identity.json publicKey does not match privateKeyB64; refusing it',
        );
        return null;
      }

      return Ed25519Identity._(
        keyPair: keyPair,
        publicKey: publicKey,
        deviceId: deviceId,
        directory: file.parent,
        algorithm: ed25519,
      );
    } catch (error, stack) {
      coreLog.fine('identity.json parse failed', error, stack);
      return null;
    }
  }

  static Future<Ed25519Identity> _create(Directory dir, File file) async {
    final ed25519 = Ed25519();
    final keyPair = await ed25519.newKeyPair();
    final seed = List<int>.from(await keyPair.extractPrivateKeyBytes());
    final publicKey = rawEd25519PublicKey(await keyPair.extractPublicKey());
    final deviceId = _hex(_randomBytes(_deviceIdBytes));

    final json = jsonEncode(<String, String>{
      'deviceId': deviceId,
      'publicKey': base64.encode(publicKey),
      'privateKeyB64': base64.encode(seed),
    });
    await _atomicWrite(file, '$json\n');

    coreLog.info('generated new device identity $deviceId');
    return Ed25519Identity._(
      keyPair: keyPair,
      publicKey: publicKey,
      deviceId: deviceId,
      directory: dir,
      algorithm: ed25519,
    );
  }

  /// Stable 128-bit identifier, lowercase hex (32 characters).
  @override
  String get deviceId => _deviceId;

  /// Base64 of the 32 raw Ed25519 public key bytes.
  ///
  /// `DeviceIdentity.publicKey` and `PeerInfo.publicKey` both describe this as
  /// "SubjectPublicKeyInfo" while also requiring 32 bytes — those are not the
  /// same thing (SPKI DER is 44 bytes). This follows the 32-byte reading,
  /// because that is what the models' own doc comment pins down and what
  /// `PeerInfo.hashPublicKey` expects to be able to hash directly.
  @override
  String get publicKey => base64.encode(_publicKey);

  /// A fresh 128-bit random value, base64url without padding.
  ///
  /// Must be unpredictable per call: it is mixed into the pairing transcript so
  /// a code observed in one session cannot be replayed in a later one.
  @override
  String freshNonce() {
    final nonce = _randomBytes(_nonceBytes);
    return base64Url.encode(nonce).replaceAll('=', '');
  }

  /// Ed25519 signature over the UTF-8 bytes of [payload], base64.
  @override
  Future<String> sign(String payload) async {
    final signature = await _ed25519.sign(
      utf8.encode(payload),
      keyPair: _keyPair,
    );
    return base64.encode(signature.bytes);
  }

  /// Verifies a base64 Ed25519 signature made by this device's key.
  ///
  /// Returns `false` — never throws — for malformed input. This runs on data
  /// that arrived from the network, so a `FormatException` here would be an
  /// attacker-triggerable crash rather than a bug report.
  @override
  Future<bool> verify(String payload, String signatureB64) async {
    try {
      final signature = base64Decode(signatureB64);
      if (signature.length != _signatureBytes) {
        coreLog.fine(
          'rejecting signature of ${signature.length} bytes, expected '
          '$_signatureBytes',
        );
        return false;
      }
      return await _ed25519.verify(
        utf8.encode(payload),
        signature: Signature(
          signature,
          publicKey: SimplePublicKey(_publicKey, type: KeyPairType.ed25519),
        ),
      );
    } catch (error, stack) {
      coreLog.fine('verify failed on malformed input', error, stack);
      return false;
    }
  }

  /// Fresh throwaway TLS material for one session. Never persisted.
  @override
  Future<SessionCredentials> beginSession() =>
      EphemeralCertAuthority().issue();

  /// Directory holding [fileName]. Useful for diagnostics and tests.
  Directory get directory => _directory;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

final Random _random = Random.secure();

Uint8List _randomBytes(int length) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = _random.nextInt(256);
  }
  return out;
}

String _hex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

bool _isHex(String value, int length) {
  if (value.length != length) return false;
  for (var i = 0; i < value.length; i++) {
    final c = value.codeUnitAt(i);
    final isDigit = c >= 0x30 && c <= 0x39;
    final isLowerHex = c >= 0x61 && c <= 0x66;
    if (!isDigit && !isLowerHex) return false;
  }
  return true;
}

/// Length-independent byte comparison. Not constant-time, and does not need to
/// be: both inputs are our own public key, not a secret, and there is no
/// attacker-controlled guess to leak through timing here.
bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Write to a sibling `.tmp` then `rename` over the target.
///
/// `rename` is atomic within a directory on every filesystem this app targets,
/// so a crash leaves either no file or the complete previous file — never a
/// half-written one. `flush` before the rename forces the bytes out of the
/// process buffer, otherwise the rename can land before the data does.
Future<void> _atomicWrite(File target, String contents) async {
  final tmp = File('${target.path}.tmp');
  final handle = await tmp.open(mode: FileMode.writeOnly);
  try {
    await handle.writeString(contents);
    await handle.flush();
  } finally {
    await handle.close();
  }
  await tmp.rename(target.path);
}