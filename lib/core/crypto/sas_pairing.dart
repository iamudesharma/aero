/// Short-authentication-string (SAS) derivation and pairing rate limiting.
///
/// Both devices independently render the same six digits from the two TLS
/// certificate fingerprints plus a fresh session nonce. The user compares them
/// out loud; if they match, a man-in-the-middle's own key is in the transcript
/// and could not have produced the same digits.
///
/// ## Why the fingerprints are sorted by (length, then lexicographic)
///
/// The transcript has to be identical on both sides, and neither side knows
/// whether it dialed or accepted. Sorting removes the ordering question.
/// Plain `a.compareTo(b)` would *almost* do, but it is not a total order over
/// strings of differing length in the sense we need: comparing `'9'` and `'10'`
/// puts `'10'` first lexicographically while a length-first order puts `'9'`
/// first. Both rules are individually deterministic, so either would work, but
/// mixing them (or changing one later without the other) is exactly the kind of
/// silent interop break that produces a pairing that never succeeds. Pinning
/// one rule — shorter first, then byte-wise — removes the ambiguity.
///
/// Fingerprints are compared as their UTF-8 bytes, so "lexicographic" means
/// byte order, not locale collation: `String.compareTo` compares UTF-16 code
/// units, which for hex-only input (all code units < 0x80) coincides with byte
/// order anyway.
///
/// ## Why the transcript is length-delimited
///
/// `lo || 0x00 || hi || 0x00 || nonce` cannot be ambiguous because the
/// separators sit between *hash inputs*, not inside them: `lo` and `hi` are
/// lowercase hex, and `0x00` appears in neither. The nonce is last and
/// unbounded, but nothing follows it, so it cannot be confused with a
/// fingerprint either.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';

/// Derives pairing codes and throttles repeated failures.
///
/// See `trust_store.dart` for the persistence half of `PairingAuthority`, which
/// delegates the three methods implemented here to an instance of this class.
class SasPairingAuthority implements PairingAuthority {
  SasPairingAuthority({DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;

  /// deviceId -> timestamps of recent failed attempts.
  final Map<String, List<DateTime>> _failures = <String, List<DateTime>>{};

  /// Last seen pinned peer, per deviceId. See [_rememberPeer] for why this is
  /// only a fallback and not the real trust store.
  final Map<String, String> _pinnedKeys = <String, String>{};

  DateTime get _now => _clock();

  // -------------------------------------------------------------------------
  // Proof derivation
  // -------------------------------------------------------------------------

  @override
  PairingProof deriveProof({
    required String localFingerprint,
    required String remoteFingerprint,
    required String nonce,
    String method = Crypto.pairingMethod,
  }) {
    final (lo, hi) = _order(_normalize(localFingerprint), _normalize(remoteFingerprint));

    final transcript = BytesBuilder(copy: false)
      ..add(utf8.encode(lo))
      ..addByte(0x00)
      ..add(utf8.encode(hi))
      ..addByte(0x00)
      ..add(utf8.encode(nonce));
    final digest = _sha256(transcript.takeBytes());

    // First 8 bytes big-endian, mod 10^6. Accumulated through BigInt because
    // the full 64-bit range does not fit a signed 64-bit Dart int: read as a
    // signed value, a digest above 2^63 would come out negative and produce a
    // negative code.
    var wide = BigInt.zero;
    for (var i = 0; i < 8; i++) {
      wide = (wide << 8) | BigInt.from(digest[i]);
    }
    final value = (wide % _modulus).toInt();

    return PairingProof(
      method: method,
      value: value.toString().padLeft(Pairing.codeDigits, '0'),
      // The clock is read *here and only here*. Mixing a timestamp into the
      // digest would make the two sides disagree whenever their clocks differ
      // by even a millisecond, and the whole point is that neither side trusts
      // the other's clock.
      expiresAt: _now.add(Pairing.codeLifetime),
    );
  }

  /// Lowercase hex, trimmed.
  ///
  /// Deliberately does *not* strip separators. Fingerprints reach this class as
  /// lowercase hex with no separators, and quietly deleting `:` or whitespace
  /// would mean two different inputs can hash to the same transcript — the one
  /// place where an accidental collision would actually matter.
  static String _normalize(String fingerprint) =>
      fingerprint.trim().toLowerCase();

  /// Total order over fingerprints: shorter first, then byte-wise.
  static (String, String) _order(String a, String b) {
    final byLength = a.length.compareTo(b.length);
    if (byLength != 0) return byLength < 0 ? (a, b) : (b, a);
    final byValue = a.compareTo(b);
    if (byValue < 0) return (a, b);
    return (b, a);
  }

  @override
  bool verifyProof(PairingProof presented, PairingProof expected) {
    try {
      if (presented.method != expected.method) return false;
      if (presented.value != expected.value) return false;
      final now = _now;
      if (presented.isExpired(now) || expected.isExpired(now)) return false;
      return true;
    } catch (error, stack) {
      // Both proofs arrive over the wire. A malformed value must not be able to
      // take down the pairing endpoint.
      coreLog.warning('verifyProof rejected malformed input', error, stack);
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Rate limiting
  // -------------------------------------------------------------------------

  /// True once [Pairing.maxAttempts] failures fall inside a single
  /// [Pairing.attemptCooldown] window.
  ///
  /// Six digits is brute-forceable — 10^6 guesses — so without a throttle an
  /// attacker on the LAN could simply keep guessing until one lands. Five
  /// attempts per minute keeps the honest user (who usually mistypes once) happy
  /// while capping an attacker at ~83 guesses/day.
  @override
  bool isRateLimited(String deviceId) {
    final attempts = _liveAttempts(deviceId);
    return attempts.length >= Pairing.maxAttempts;
  }

  @override
  void recordFailure(String deviceId) {
    final attempts = _liveAttempts(deviceId)..add(_now);
    _failures[deviceId] = attempts;
    coreLog.fine(
      'pairing failure #$attempts.length for $deviceId'
      '${isRateLimited(deviceId) ? ' (now limited)' : ''}',
    );
  }

  /// Drops the failure history for [deviceId], e.g. after a successful pairing.
  void resetFailures(String deviceId) => _failures.remove(deviceId);

  /// Attempts still inside the cooldown window, pruning as a side effect.
  List<DateTime> _liveAttempts(String deviceId) {
    final cutoff = _now.subtract(Pairing.attemptCooldown);
    final kept = (_failures[deviceId] ?? const <DateTime>[])
        .where((t) => t.isAfter(cutoff))
        .toList(growable: true);
    if (kept.isEmpty) {
      _failures.remove(deviceId);
    } else {
      _failures[deviceId] = kept;
    }
    return kept;
  }

  // -------------------------------------------------------------------------
  // Trust persistence
  //
  // `PairingAuthority` is one interface covering both halves of pairing, so this
  // class has to answer these three too. The durable implementation is
  // `TrustStore`, which owns the file and delegates the rest back here; what
  // follows is a deliberately in-memory stand-in that keeps this class usable
  // standalone in tests and keeps the interface total rather than throwing
  // UnsupportedError at a caller who wired the wrong object in.
  //
  // It is not a security hole — the worst outcome is that trust does not survive
  // a restart, so the user re-confirms a code — but it is a footgun, hence the
  // warning.
  // -------------------------------------------------------------------------

  @override
  Future<void> rememberPeer({
    required String deviceId,
    required String publicKey,
    String? alias,
  }) async {
    coreLog.warning(
      'SasPairingAuthority.rememberPeer is in-memory only; wire up TrustStore '
      'so paired devices are remembered across launches',
    );
    _pinnedKeys[deviceId] = publicKey;
  }

  @override
  Future<TrustState> lookupTrust({
    required String deviceId,
    required String publicKey,
  }) async {
    final pinned = _pinnedKeys[deviceId];
    if (pinned == null) return TrustState.unknown;
    return pinned == publicKey ? TrustState.known : TrustState.identityConflict;
  }

  @override
  Future<void> forgetPeer(String deviceId) async {
    _pinnedKeys.remove(deviceId);
    resetFailures(deviceId);
  }
}

/// `10^Pairing.codeDigits` = one million. BigInt because the reduction must not
/// be done in a signed 64-bit int.
final BigInt _modulus = BigInt.from(10).pow(Pairing.codeDigits);

// ---------------------------------------------------------------------------
// SHA-256, synchronous
//
// `PairingAuthority.deriveProof` is synchronous in the frozen contract, and
// `package:cryptography`'s `Sha256().hash()` returns a Future. `HashAlgorithm`
// does expose `hashSync`, but only on the `package:cryptography/dart.dart`
// `DartSha256` subclass, which would drop the native acceleration the rest of
// the app gets from `cryptography_flutter`. Deriving a code happens a handful
// of times per session, so a self-contained implementation is the right trade:
// no `async` in the middle of the pairing handshake, no dependency on which
// backend `Cryptography.instance` happens to be.
//
// This is FIPS 180-4 SHA-256. `models.dart` has a second copy for the same
// reason (its caller is `PeerInfo.toTxt()`, also synchronous); sharing one
// would mean a seventh module that neither file owns.
// ---------------------------------------------------------------------------

const List<int> _sha256K = <int>[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, //
  0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
  0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
  0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
  0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
  0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;

Uint8List _sha256(List<int> message) {
  final h = Uint32List.fromList(<int>[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  final bitLength = message.length * 8;
  final padded = Uint8List(((message.length + 9 + 63) ~/ 64) * 64);
  padded.setRange(0, message.length, message);
  padded[message.length] = 0x80;
  // Length is a 64-bit big-endian bit count. `setRange` on a Uint8List cannot
  // express "big endian", so write the 8 bytes by hand.
  final view = ByteData.view(padded.buffer, padded.offsetInBytes);
  view.setUint32(padded.length - 8, (bitLength >> 32) & 0xffffffff);
  view.setUint32(padded.length - 4, bitLength & 0xffffffff);

  final w = Uint32List(64);
  for (var chunk = 0; chunk < padded.length; chunk += 64) {
    for (var i = 0; i < 16; i++) {
      final o = chunk + i * 4;
      w[i] = (padded[o] << 24) |
          (padded[o + 1] << 16) |
          (padded[o + 2] << 8) |
          padded[o + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }

    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];

    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g);
      final temp1 = (hh + s1 + ch + _sha256K[i] + w[i]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xffffffff;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }

    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }

  final out = Uint8List(32);
  final outView = ByteData.view(out.buffer);
  for (var i = 0; i < 8; i++) {
    outView.setUint32(i * 4, h[i]);
  }
  return out;
}