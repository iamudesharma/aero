/// Ephemeral, self-signed X.509 credentials for one TLS session.
///
/// ## Why a hand-rolled DER encoder instead of a library
///
/// `package:cryptography` gives us Ed25519 *primitives* (keygen, sign, verify,
/// hash) but no X.509 builder — there is no `X509Certificate`, no `Certificate`
/// type and no ASN.1 writer anywhere in the package tree. Meanwhile `dart:io`'s
/// [SecurityContext] is the only consumer we have: it needs a genuine, parseable
/// certificate and PKCS#8 private key. So this file implements the smallest
/// possible DER/ASN.1 writer that can express an RFC 5280 certificate wrapping
/// an ECDSA P-256 key.
///
/// The output is validated against a real OpenSSL 3.x parser and against a real
/// [SecurityContext] (see `test/ed25519_identity_test.dart` and
/// `test/ephemeral_certificate_test.dart`). Prefer this to pulling in a
/// certificate dependency that would need to be kept alive for a structure that
/// never changes.
///
/// ## Why ECDSA P-256 and not Ed25519
///
/// The certificate exists purely to let two peers exchange a fingerprint. The
/// device's durable *identity* is Ed25519 (see `ed25519_identity.dart`) and does
/// not touch TLS. But the TLS certificate cannot be Ed25519:
///
/// Dart's BoringSSL **server** serves Ed25519 certificates fine, but Dart's
/// BoringSSL **client** does not advertise `ed25519` in its
/// `signature_algorithms` extension. A Dart client therefore refuses a
/// Dart/OpenSSL Ed25519 server certificate with a bare
/// `HandshakeException: Connection terminated during handshake`, even though the
/// certificate parses perfectly. ECDSA P-256 is in every signature-algorithm
/// set, so it is what a peer presents during the TLS handshake.
///
/// ## Where the ECDSA implementation comes from
///
/// The installed `package:cryptography` (2.9.0) ships Ed25519 in pure Dart but
/// leaves its pure-Dart `Ecdsa` and `Ecdh` implementations as
/// `UnimplementedError`; the native implementation only exists in
/// `cryptography_flutter`, which is not available to `flutter test` (no plugin
/// registration, no host binaries). P-256 field/point arithmetic plus ECDSA
/// signing is therefore implemented below using `BigInt`. It is a small,
/// self-contained, dependency-free implementation used only to mint one
/// throwaway certificate per session; the durable Ed25519 identity, its
/// signing, and all long-lived crypto remain exactly as they were.
///
/// ## Fingerprint definition (important — both peers must agree)
///
/// `SessionCredentials.fingerprintHex` is **SHA-256 over the DER (binary) form
/// of the certificate**, lowercase hex — *not* over the PEM text.
///
/// That choice is deliberate:
///
///  * A peer observes the certificate on the wire as DER. Dart exposes the
///    peer's certificate to the transport as [X509Certificate] (with `.der` /
///    `.pem`), so `PeerLink.remoteCertFingerprint` can hash exactly the bytes
///    this authority produced and the two will agree bit for bit.
///  * Hashing the PEM text instead would work too (both sides run this code),
///    but it would not match the fingerprint of the identical certificate as
///    seen by OpenSSL, `SecurityContext`, or any future TLS-level pin. DER is
///    the canonical serialisation, so DER is what we hash.
///
/// ## Why the certificate is never persisted
///
/// It is regenerated per session on purpose. Persisting a TLS certificate (and
/// therefore reusing a private key) would let an attacker who records one
/// session's traffic in the clear later replay a whole recorded session, and
/// it would make the pairing code replayable. See `PairingProof` in
/// `lib/core/models.dart` for the other half of that argument.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../contracts.dart';
import '../logging.dart';

/// Mints a throwaway self-signed certificate + key pair, in memory only.
///
/// Safe to construct one per session: there is no state to carry between calls.
class EphemeralCertAuthority {
  EphemeralCertAuthority({
    this.commonName = 'aero-ephemeral',
    this.lifetime = const Duration(days: 1),
    DateTime Function()? clock,
    Random? random,
  })  : _clock = clock ?? DateTime.now,
        _random = random ?? Random.secure();

  /// Subject/issuer common name. Purely cosmetic — it is never used for
  /// identity. Pairing authenticates the *fingerprint*, not the name, because
  /// both certificates are self-signed and the name is attacker-chosen.
  final String commonName;

  /// How long the generated certificate claims to be valid.
  final Duration lifetime;

  final DateTime Function() _clock;
  final Random _random;

  /// Generates a fresh ECDSA P-256 certificate and matching PKCS#8 private key.
  ///
  /// The private key is never written to disk and never leaves this process.
  Future<SessionCredentials> issue() async {
    final keyPair = _P256KeyPair.generate(_random);
    final publicKeyPoint = keyPair.publicKeyUncompressed;

    // A random 64-bit serial. The top bit is cleared so the DER INTEGER stays
    // exactly 8 bytes (a set high bit would force a 9th `0x00` padding byte).
    // RFC 5280 s4.1.2.2 requires the serial to be positive and <= 20 octets.
    final serial = _randomBytes(8, _random);
    serial[0] &= 0x7f;

    // Backdate slightly so a peer whose clock runs a little behind still
    // accepts the certificate.
    final now = _clock().toUtc();
    final notBefore = now.subtract(const Duration(hours: 1));
    final notAfter = now.add(lifetime);

    final tbs = _tbsCertificate(
      serial: serial,
      subjectPublicKey: publicKeyPoint,
      commonName: commonName,
      notBefore: notBefore,
      notAfter: notAfter,
    );

    // RFC 5280 s4.1.1.2: the signature covers the DER encoding of tbsCertificate
    // *including* its SEQUENCE header, exactly as encoded here. ECDSA signs the
    // SHA-256 digest of those bytes.
    final digest = await Sha256().hash(tbs);
    final signature = keyPair.signDigest(digest.bytes, _random);
    final der = _certificate(tbs: tbs, signature: signature);
    final fingerprint = await Sha256().hash(der);
    final fingerprintHex = _hex(fingerprint.bytes);
    coreLog.fine(
      'ephemeral certificate issued; pairing fingerprint is SHA-256(DER)='
      '$fingerprintHex',
    );

    return SessionCredentials(
      certificatePem: _pem('CERTIFICATE', der),
      privateKeyPem: _pem('PRIVATE KEY', keyPair.pkcs8()),
      fingerprintHex: fingerprintHex,
      publicKeyB64: base64.encode(publicKeyPoint),
      signatureAlgorithm: 'ecdsa-p256',
    );
  }
}

// ---------------------------------------------------------------------------
// P-256 (secp256r1 / prime256v1) and ECDSA-SHA256
//
// Domain parameters from FIPS 186-4 / SEC 2. Only what is needed to mint a
// self-signed certificate is implemented: key generation and signing. Point
// arithmetic is in Jacobian coordinates so a scalar multiplication costs a
// single modular inversion at the end.
//
// This is not constant-time, and does not need to be for this use: the key is
// thrown away at the end of the session and never protects a durable secret.
// The long-lived Ed25519 identity is untouched by any of it.
// ---------------------------------------------------------------------------

final BigInt _p256P = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);
final BigInt _p256N = BigInt.parse(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  radix: 16,
);
final BigInt _p256Gx = BigInt.parse(
  '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
  radix: 16,
);
final BigInt _p256Gy = BigInt.parse(
  '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  radix: 16,
);
final _P256Jacobian _p256Generator =
    _P256Jacobian(_p256Gx, _p256Gy, BigInt.one);

BigInt _p256Mod(BigInt value) {
  final reduced = value % _p256P;
  return reduced.isNegative ? reduced + _p256P : reduced;
}

/// A point in Jacobian coordinates: `x = X/Z^2`, `y = Y/Z^3`.
///
/// `Z == 0` is the point at infinity.
class _P256Jacobian {
  const _P256Jacobian(this.x, this.y, this.z);

  final BigInt x;
  final BigInt y;
  final BigInt z;

  static final _P256Jacobian infinity =
      _P256Jacobian(BigInt.one, BigInt.one, BigInt.zero);

  bool get isInfinity => z == BigInt.zero;

  /// Point doubling, specialised for `a = -3` (`add-2007-bl` is for addition).
  _P256Jacobian double_() {
    if (isInfinity || y == BigInt.zero) return infinity;
    final delta = _p256Mod(z * z); // Z^2
    final gamma = _p256Mod(y * y); // Y^2
    final beta = _p256Mod(x * gamma); // X*Y^2
    final alpha = _p256Mod(
      BigInt.from(3) * _p256Mod(x - delta) * _p256Mod(x + delta),
    ); // 3*(X-Z^2)*(X+Z^2)
    final x3 = _p256Mod(alpha * alpha - BigInt.from(8) * beta);
    final y3 = _p256Mod(
      alpha * (BigInt.from(4) * beta - x3) -
          BigInt.from(8) * gamma * gamma,
    );
    final z3 = _p256Mod(BigInt.from(2) * y * z);
    return _P256Jacobian(x3, y3, z3);
  }

  /// Point addition (`add-2007-bl`).
  _P256Jacobian add(_P256Jacobian other) {
    if (isInfinity) return other;
    if (other.isInfinity) return this;
    final z1z1 = _p256Mod(z * z);
    final z2z2 = _p256Mod(other.z * other.z);
    final u1 = _p256Mod(x * z2z2);
    final u2 = _p256Mod(other.x * z1z1);
    final s1 = _p256Mod(y * other.z * z2z2);
    final s2 = _p256Mod(other.y * z * z1z1);
    if (u1 == u2) {
      if (s1 != s2) return infinity; // P + (-P)
      return double_(); // P == Q
    }
    final h = _p256Mod(u2 - u1);
    final twoH = _p256Mod(BigInt.from(2) * h);
    final i = _p256Mod(twoH * twoH);
    final j = _p256Mod(h * i);
    final r = _p256Mod(BigInt.from(2) * (s2 - s1));
    final v = _p256Mod(u1 * i);
    final x3 = _p256Mod(r * r - j - BigInt.from(2) * v);
    final y3 = _p256Mod(r * (v - x3) - BigInt.from(2) * s1 * j);
    final z3 = _p256Mod(
      _p256Mod((z + other.z) * (z + other.z) - z1z1 - z2z2) * h,
    );
    return _P256Jacobian(x3, y3, z3);
  }

  /// Converts to affine coordinates, inverting `Z` exactly once.
  (BigInt, BigInt) toAffine() {
    if (isInfinity) {
      throw StateError('cannot convert the point at infinity to affine form');
    }
    final zInv = z.modInverse(_p256P);
    final zInv2 = _p256Mod(zInv * zInv);
    final affineX = _p256Mod(x * zInv2);
    final affineY = _p256Mod(y * zInv2 * zInv);
    return (affineX, affineY);
  }
}

/// Double-and-add scalar multiplication. `scalar` is assumed positive.
_P256Jacobian _p256ScalarMultiply(BigInt scalar, _P256Jacobian point) {
  var result = _P256Jacobian.infinity;
  for (var i = scalar.bitLength - 1; i >= 0; i--) {
    result = result.double_();
    if (((scalar >> i) & BigInt.one) == BigInt.one) {
      result = result.add(point);
    }
  }
  return result;
}

/// Uniformly random scalar in `[1, n-1]`, by rejection sampling.
BigInt _p256RandomScalar(Random random) {
  while (true) {
    final candidate = _bytesToBigInt(_randomBytes(32, random));
    if (candidate > BigInt.zero && candidate < _p256N) return candidate;
  }
}

/// An in-memory P-256 key pair, able to sign with ECDSA-SHA256.
class _P256KeyPair {
  _P256KeyPair(this._d, this._x, this._y);

  final BigInt _d;
  final BigInt _x;
  final BigInt _y;

  factory _P256KeyPair.generate(Random random) {
    final d = _p256RandomScalar(random);
    final (x, y) = _p256ScalarMultiply(d, _p256Generator).toAffine();
    return _P256KeyPair(d, x, y);
  }

  /// `0x04 || X(32) || Y(32)`, the standard X9.62 uncompressed point.
  List<int> get publicKeyUncompressed => <int>[
        0x04,
        ..._fixedLengthBytes(_x, 32),
        ..._fixedLengthBytes(_y, 32),
      ];

  /// ECDSA signature over [digest], DER-encoded as `SEQUENCE { r, s }`.
  ///
  /// The caller is responsible for hashing the message with SHA-256; this
  /// method applies the ECDSA equations to the already-computed digest.
  List<int> signDigest(List<int> digest, Random random) {
    final z = _bytesToBigInt(digest);
    while (true) {
      final k = _p256RandomScalar(random);
      final (x1, _) = _p256ScalarMultiply(k, _p256Generator).toAffine();
      final r = x1 % _p256N;
      if (r == BigInt.zero) continue;
      final s = (k.modInverse(_p256N) * (z + r * _d)) % _p256N;
      if (s == BigInt.zero) continue;
      return _derSignature(r, s);
    }
  }

  /// RFC 5958 PKCS#8 private key, wrapping an RFC 5915 ECPrivateKey.
  Uint8List pkcs8() => _tlv(_tagSequence, <int>[
        ..._integer(const <int>[0]),
        ..._ecAlgorithmId(),
        ..._tlv(
          _tagOctetString,
          _tlv(_tagSequence, <int>[
            ..._integer(const <int>[1]),
            ..._tlv(_tagOctetString, _fixedLengthBytes(_d, 32)),
            ..._tlv(0xa0, _oidP256),
            ..._tlv(0xa1, _bitString(publicKeyUncompressed)),
          ]),
        ),
      ]);
}

/// ECDSA signature as DER `SEQUENCE { INTEGER r, INTEGER s }`.
Uint8List _derSignature(BigInt r, BigInt s) => _tlv(_tagSequence, <int>[
      ..._integer(_minimalBytes(r)),
      ..._integer(_minimalBytes(s)),
    ]);

BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

/// Big-endian, exactly [length] bytes, left-padded with zeroes.
List<int> _fixedLengthBytes(BigInt value, int length) {
  final out = List<int>.filled(length, 0);
  var remaining = value;
  for (var i = length - 1; i >= 0 && remaining > BigInt.zero; i--) {
    out[i] = (remaining & BigInt.from(0xff)).toInt();
    remaining = remaining >> 8;
  }
  return out;
}

/// Big-endian, minimal length, no leading zeroes (zero -> `[0]`).
List<int> _minimalBytes(BigInt value) {
  if (value == BigInt.zero) return <int>[0];
  final bytes = <int>[];
  var remaining = value;
  while (remaining > BigInt.zero) {
    bytes.insert(0, (remaining & BigInt.from(0xff)).toInt());
    remaining = remaining >> 8;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// The ASN.1 structures being emitted
//
// Everything below is DER (Distinguished Encoding Rules) from ITU-T X.690:
//   TLV := Tag (1 byte) || Length (short/long form) || Content
//
// Tag numbers we need (class = universal/context, constructed bit set for
// SEQUENCE/SET and for context tags that wrap an explicit value):
//
//   0x01 BOOLEAN          0x02 INTEGER        0x03 BIT STRING
//   0x04 OCTET STRING     0x06 OID           0x0c UTF8String
//   0x17 UTCTime          0x18 GeneralizedTime
//   0x30 SEQUENCE         0x31 SET
//   0xA0 [0] constructed  0xA1 [1] constructed  0xA3 [3] constructed
//
// The three documents we emit:
//
// 1. SubjectPublicKeyInfo (RFC 5480 s2)
//      SEQUENCE { AlgorithmIdentifier, BIT STRING publicKey }
//      The P-256 AlgorithmIdentifier carries the curve as a second OID
//      parameter (unlike Ed25519, whose parameters must be absent):
//      SEQUENCE { OID id-ecPublicKey, OID prime256v1 }.
//      Encodes as 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48
//      ce 3d 03 01 07 03 42 00 04 <X 32> <Y 32>.
//
// 2. PKCS#8 PrivateKeyInfo (RFC 5958 s2) wrapping an ECPrivateKey (RFC 5915)
//      SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING privateKey }
//      The inner ECPrivateKey is
//      SEQUENCE { INTEGER 1, OCTET STRING d, [0] curve OID, [1] BIT STRING Q }.
//      BoringSSL parses this with `d2i_PrivateKey`, and it checks that the key
//      matches the certificate, so `d` and `Q` must both be correct.
//
// 3. Certificate (RFC 5280 s4.1)
//      SEQUENCE { tbsCertificate, AlgorithmIdentifier, BIT STRING signature }
//      TBSCertificate (RFC 5280 s4.1) is
//      SEQUENCE {
//        [0] EXPLICIT INTEGER 2,          -- v3
//        INTEGER serialNumber,
//        AlgorithmIdentifier,            -- ecdsa-with-SHA256, must equal outer
//        issuer Name,
//        Validity,
//        subject Name,
//        subjectPublicKeyInfo,
//        [3] EXPLICIT Extensions
//      }
//      Name is an RDNSequence holding one CN (2.5.4.3) as a UTF8String.
//      Validity holds two absolute times, so the client can never be
//      confused into reading a UTCTime/generalTime choice differently.
//      Extensions carries critical basicConstraints (CA:FALSE) and keyUsage
//      (digitalSignature): a leaf that claims no CA power and only signs.
//      The signature BIT STRING content is the DER `SEQUENCE { r, s }`.
//
// OIDs are hard-coded DER TLVs. There are only a handful and each is a
// constant, so a general OID encoder would be dead weight.
// ---------------------------------------------------------------------------

const int _tagBoolean = 0x01;
const int _tagInteger = 0x02;
const int _tagBitString = 0x03;
const int _tagOctetString = 0x04;
const int _tagUtf8String = 0x0c;
const int _tagUtcTime = 0x17;
const int _tagGeneralizedTime = 0x18;
const int _tagSequence = 0x30;
const int _tagSet = 0x31;

/// OID 1.2.840.10045.2.1 — id-ecPublicKey. RFC 5480 s2.1.1.
const List<int> _oidEcPublicKey = [
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];

/// OID 1.2.840.10045.3.1.7 — prime256v1 / P-256. RFC 5480 s2.1.1.1.
const List<int> _oidP256 = [
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

/// OID 1.2.840.10045.4.3.2 — ecdsa-with-SHA256. RFC 5758 s3.2.
///
/// Its AlgorithmIdentifier MUST omit the parameters field entirely; a `NULL`
/// here is a common mistake that some parsers reject.
const List<int> _oidEcdsaWithSha256 = [
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// OID 2.5.4.3 — id-at-commonName.
const List<int> _oidCommonName = [0x06, 0x03, 0x55, 0x04, 0x03];

/// OID 2.5.29.19 — id-ce-basicConstraints.
const List<int> _oidBasicConstraints = [0x06, 0x03, 0x55, 0x1d, 0x13];

/// OID 2.5.29.15 — id-ce-keyUsage.
const List<int> _oidKeyUsage = [0x06, 0x03, 0x55, 0x1d, 0x0f];

/// True for the Ed25519 SubjectPublicKeyInfo prefix
/// `SEQUENCE { SEQUENCE { OID }, BIT STRING }` followed by a 32-byte key.
const List<int> _spkiEd25519Prefix = [
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, //
  0x03, 0x21, 0x00,
];

/// Unwraps the 32 raw bytes of an Ed25519 public key from whatever
/// [KeyPair.extractPublicKey] hands back.
///
/// `cryptography`'s pure-Dart implementation returns a [SimplePublicKey] whose
/// `.bytes` are already the raw 32-byte key, but the native
/// `cryptography_flutter` backend (and some other [PublicKey]
/// implementations) return a full SubjectPublicKeyInfo DER blob instead. Both
/// are 32 bytes vs. 44 bytes, so the two are easy to tell apart — and getting it
/// wrong silently produces a public key that no signature verifies against, so
/// this is worth handling explicitly rather than assuming one shape.
///
/// Shared with `ed25519_identity.dart`; duplicated rather than exported because
/// neither file should own the other's public surface.
Uint8List rawEd25519PublicKey(PublicKey publicKey) {
  if (publicKey is! SimplePublicKey) {
    throw StateError(
      'Ed25519 key yielded a ${publicKey.runtimeType}, not a SimplePublicKey',
    );
  }
  final bytes = publicKey.bytes;
  if (bytes.length == 32) return Uint8List.fromList(bytes);
  if (bytes.length == 44 && _startsWith(bytes, _spkiEd25519Prefix)) {
    // SubjectPublicKeyInfo: the raw key is always the trailing 32 bytes.
    return Uint8List.fromList(bytes.sublist(bytes.length - 32));
  }
  throw StateError(
    'Unrecognised Ed25519 public key encoding (${bytes.length} bytes)',
  );
}

bool _startsWith(List<int> bytes, List<int> prefix) {
  if (bytes.length < prefix.length) return false;
  for (var i = 0; i < prefix.length; i++) {
    if (bytes[i] != prefix[i]) return false;
  }
  return true;
}

/// DER tag-length-value. Long-form lengths are used only past 127 bytes.
Uint8List _tlv(int tag, List<int> content) {
  final length = content.length;
  final lengthOctets = <int>[];
  if (length < 0x80) {
    lengthOctets.add(length);
  } else {
    var remaining = length;
    while (remaining > 0) {
      lengthOctets.insert(0, remaining & 0xff);
      remaining >>= 8;
    }
    lengthOctets.insert(0, 0x80 | lengthOctets.length);
  }
  return Uint8List.fromList(<int>[tag, ...lengthOctets, ...content]);
}

/// DER INTEGER from a big-endian magnitude: minimal length, forced positive.
Uint8List _integer(List<int> magnitude) {
  var bytes = List<int>.of(magnitude);
  while (bytes.length > 1 && bytes.first == 0) {
    bytes = bytes.sublist(1);
  }
  if (bytes.isEmpty) bytes = <int>[0];
  if (bytes.first & 0x80 != 0) {
    // High bit set means DER would read it as negative without padding.
    bytes.insert(0, 0);
  }
  return _tlv(_tagInteger, bytes);
}

/// DER BIT STRING. [unusedBits] is the count of trailing bits to ignore.
Uint8List _bitString(List<int> bytes, {int unusedBits = 0}) =>
    _tlv(_tagBitString, <int>[unusedBits, ...bytes]);

/// `AlgorithmIdentifier` for ECDSA P-256 (RFC 5480): the curve OID is the
/// algorithm's parameter.
Uint8List _ecAlgorithmId() =>
    _tlv(_tagSequence, <int>[..._oidEcPublicKey, ..._oidP256]);

/// `AlgorithmIdentifier` for ecdsa-with-SHA256: the OID alone, no parameters.
Uint8List _signatureAlgorithmId() => _tlv(_tagSequence, _oidEcdsaWithSha256);

/// RFC 5480 SubjectPublicKeyInfo for an ECDSA P-256 key.
Uint8List _subjectPublicKeyInfo(List<int> publicKey) => _tlv(
      _tagSequence,
      <int>[..._ecAlgorithmId(), ..._bitString(publicKey)],
    );

/// X.501 `Name` (an RDNSequence) holding exactly one CN attribute.
Uint8List _name(String commonName) {
  final attribute = _tlv(
    _tagSequence,
    <int>[..._oidCommonName, ..._tlv(_tagUtf8String, utf8.encode(commonName))],
  );
  return _tlv(_tagSequence, _tlv(_tagSet, attribute));
}

/// Absolute time, choosing the DER encoding the RFC requires for the year.
///
/// RFC 5280 s4.1.2.5: UTCTime for 1950..2049, GeneralizedTime for everything
/// else. Getting this wrong is a latent bug — `UTCTime` with `70` would parse
/// as 2070 — so both branches exist even though the app will not outlive 2049.
Uint8List _time(DateTime value) {
  final utc = value.toUtc();
  String two(int v) => v.toString().padLeft(2, '0');
  String four(int v) => v.toString().padLeft(4, '0');
  final year = utc.year;
  if (year >= 1950 && year <= 2049) {
    // YYMMDDHHMMSSZ
    final text = '${two(year % 100)}${two(utc.month)}${two(utc.day)}'
        '${two(utc.hour)}${two(utc.minute)}${two(utc.second)}Z';
    return _tlv(_tagUtcTime, utf8.encode(text));
  }
  // YYYYMMDDHHMMSSZ
  final text = '${four(year)}${two(utc.month)}${two(utc.day)}'
      '${two(utc.hour)}${two(utc.minute)}${two(utc.second)}Z';
  return _tlv(_tagGeneralizedTime, utf8.encode(text));
}

Uint8List _validity(DateTime notBefore, DateTime notAfter) =>
    _tlv(_tagSequence, <int>[..._time(notBefore), ..._time(notAfter)]);

/// `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }`
Uint8List _extension(List<int> oid, List<int> value, {bool critical = true}) =>
    _tlv(_tagSequence, <int>[
      ...oid,
      if (critical) ..._tlv(_tagBoolean, const <int>[0xff]),
      ..._tlv(_tagOctetString, value),
    ]);

/// `basicConstraints` (critical, CA absent = FALSE) and `keyUsage` (critical,
/// bit 0 = digitalSignature). `[0x80]` with 7 unused trailing bits is exactly
/// the DER BIT STRING for digitalSignature.
Uint8List _extensions() => _tlv(_tagSequence, <int>[
      ..._extension(
        _oidBasicConstraints,
        _tlv(_tagSequence, const <int>[]),
      ),
      ..._extension(
        _oidKeyUsage,
        _bitString(const <int>[0x80], unusedBits: 7),
      ),
    ]);

Uint8List _tbsCertificate({
  required List<int> serial,
  required List<int> subjectPublicKey,
  required String commonName,
  required DateTime notBefore,
  required DateTime notAfter,
}) =>
    _tlv(_tagSequence, <int>[
      // [0] EXPLICIT version. 2 = v3; v1 (0) cannot carry extensions.
      ..._tlv(0xa0, _integer(const <int>[2])),
      ..._integer(serial),
      // RFC 5280 s4.1.1.2: must be identical to the outer AlgorithmIdentifier.
      ..._signatureAlgorithmId(),
      ..._name(commonName),
      ..._validity(notBefore, notAfter),
      ..._name(commonName),
      ..._subjectPublicKeyInfo(subjectPublicKey),
      // [3] EXPLICIT Extensions.
      ..._tlv(0xa3, _extensions()),
    ]);

Uint8List _certificate({required Uint8List tbs, required List<int> signature}) =>
    _tlv(_tagSequence, <int>[
      ...tbs,
      ..._signatureAlgorithmId(),
      ..._bitString(signature),
    ]);

/// Wraps DER in RFC 7468 PEM with 64-character lines.
///
/// The bytes handed to [SecurityContext] must be the UTF-8 encoding of this
/// text, *not* the DER — `useCertificateChainBytes` and `usePrivateKeyBytes`
/// expect PEM.
String _pem(String label, List<int> der) {
  final body = base64.encode(der);
  final lines = <String>[];
  for (var offset = 0; offset < body.length; offset += 64) {
    lines.add(body.substring(offset, min(offset + 64, body.length)));
  }
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

Uint8List _randomBytes(int length, Random random) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = random.nextInt(256);
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
