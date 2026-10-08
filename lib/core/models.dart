/// Data models shared by every layer. These are the wire format, so any
/// change here is a protocol change - bump `kProtocolVersion` when it happens.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'constants.dart';

/// Platforms this protocol targets. `web` is a sender-only target: a page can
/// initiate a connection but nothing can initiate to a page.
enum AeroOs { macos, ios, android, windows, linux, web, unknown }

AeroOs aeroOsFromName(String name) => switch (name) {
      'macos' => AeroOs.macos,
      'ios' => AeroOs.ios,
      'android' => AeroOs.android,
      'windows' => AeroOs.windows,
      'linux' => AeroOs.linux,
      'web' => AeroOs.web,
      _ => AeroOs.unknown,
    };

/// Optional capabilities a peer advertises. A peer advertising a subset is
/// still reachable; the sender degrades rather than failing.
enum Capability {
  send,
  receive,
  multiFile,
  folder,
  resume,
  reverseTransfer;

  static Capability? fromName(String name) {
    for (final c in Capability.values) {
      if (c.name == name) return c;
    }
    return null;
  }
}

/// How much we trust that a discovered peer is who it claims to be.
/// mDNS is completely unauthenticated — anyone on the LAN can advertise any
/// name — so this starts at [unknown] for every peer.
enum TrustState {
  /// Seen for the first time; user must confirm the 6-digit code.
  unknown,

  /// Previously paired (trust-on-first-use). Key pinned locally.
  known,

  /// Conflicting key for a previously seen device id: possible impersonation
  /// or a reinstall. Never silently trust this.
  identityConflict,
}

/// Identity + metadata a peer publishes about itself (`GET /v1/info`, and the
/// subset that fits in the mDNS TXT record).
class PeerInfo {
  const PeerInfo({
    required this.deviceId,
    required this.deviceName,
    required this.os,
    required this.osVersion,
    required this.appVersion,
    required this.publicKey,
    required this.protocolVersion,
    required this.capabilities,
    required this.nonce,
    this.port = kPreferredPort,
    this.trustState = TrustState.unknown,
    this.publicKeyHash = '',
  });

  factory PeerInfo.fromJson(Map<String, dynamic> json) => PeerInfo(
        deviceId: json['deviceId'] as String? ?? '',
        deviceName: json['deviceName'] as String? ?? 'Unknown device',
        os: aeroOsFromName(json['os'] as String? ?? 'unknown'),
        osVersion: json['osVersion'] as String? ?? '',
        appVersion: json['appVersion'] as String? ?? '',
        publicKey: json['publicKey'] as String? ?? '',
        protocolVersion: (json['protocol'] as num?)?.toInt() ?? 0,
        capabilities: ((json['capabilities'] as List?) ?? const [])
            .map((e) => Capability.fromName(e.toString()))
            .whereType<Capability>()
            .toSet(),
        nonce: json['nonce'] as String? ?? '',
        port: (json['port'] as num?)?.toInt() ?? kPreferredPort,
        trustState: switch (json['trustState'] as String?) {
          'known' => TrustState.known,
          'identityConflict' => TrustState.identityConflict,
          _ => TrustState.unknown,
        },
      );

  final String deviceId;
  final String deviceName;
  final AeroOs os;
  final String osVersion;
  final String appVersion;

  /// Base64 of the 32 raw Ed25519 public key bytes.
  ///
  /// Deliberately the raw key, not SubjectPublicKeyInfo DER: SPKI for Ed25519
  /// is 44 bytes, and [hashPublicKey] hashes this value directly, so keeping it
  /// canonical avoids a decode-and-slice at every call site.
  final String publicKey;

  final int protocolVersion;
  final Set<Capability> capabilities;

  /// Fresh 128-bit random value, unique per session, mixed into the pairing
  /// code so a recorded code cannot be replayed later.
  final String nonce;

  final int port;
  final TrustState trustState;

  /// `TxtKey.publicKeyHash` from the mDNS record: a stable pseudonymous
  /// fingerprint of the peer's Ed25519 key.
  ///
  /// Only mDNS populates this — the `GET /v1/info` body does not carry it,
  /// because there the real public key is available and hashing it would be
  /// pointless. Its value is that it is available *before* pairing, so the UI
  /// can flag a peer whose key hash changed since last time (a reinstall or an
  /// impersonator) instead of only discovering it after the user has already
  /// compared codes.
  final String publicKeyHash;

  /// True when the peer's protocol major version matches ours.
  bool get isCompatible => protocolVersion == kProtocolVersion;

  bool get canReceive => capabilities.contains(Capability.receive);

  /// Compact form for the mDNS TXT record. Only what a peer-list UI needs —
  /// the nonce and full key arrive later from `GET /v1/info`.
  Map<String, String> toTxt() => {
        TxtKey.deviceId: deviceId,
        TxtKey.deviceName: deviceName,
        TxtKey.os: os.name,
        TxtKey.osVersion: osVersion,
        TxtKey.appVersion: appVersion,
        TxtKey.port: '$port',
        TxtKey.protocol: '$protocolVersion',
        TxtKey.publicKeyHash: hashPublicKey(publicKey),
        TxtKey.capabilities: capabilities.map((c) => c.name).join(','),
      };

  /// SHA-256 of the public key, base64url without padding — a stable
  /// pseudonymous handle that fits in a TXT record without leaking the key.
  ///
  /// Synchronous by necessity: `toTxt()` is called synchronously while building
  /// an mDNS record, so this cannot be awaited. The input is 32 bytes.
  static String hashPublicKey(String publicKeyB64) {
    final bytes = _tryDecode(publicKeyB64);
    if (bytes == null || bytes.isEmpty) return '';
    final digest = _sha256(bytes);
    return base64Url.encode(digest).replaceAll('=', '');
  }

  Map<String, dynamic> toJson() => {
        'protocol': protocolVersion,
        'deviceId': deviceId,
        'deviceName': deviceName,
        'os': os.name,
        'osVersion': osVersion,
        'appVersion': appVersion,
        'publicKey': publicKey,
        'port': port,
        'capabilities': capabilities.map((c) => c.name).toList(),
        'nonce': nonce,
        'trustState': trustState.name,
      };

  PeerInfo copyWith({
    String? deviceName,
    int? port,
    Set<Capability>? capabilities,
    TrustState? trustState,
    String? publicKeyHash,
  }) =>
      PeerInfo(
        deviceId: deviceId,
        deviceName: deviceName ?? this.deviceName,
        os: os,
        osVersion: osVersion,
        appVersion: appVersion,
        publicKey: publicKey,
        protocolVersion: protocolVersion,
        capabilities: capabilities ?? this.capabilities,
        nonce: nonce,
        port: port ?? this.port,
        trustState: trustState ?? this.trustState,
        publicKeyHash: publicKeyHash ?? this.publicKeyHash,
      );

  @override
  String toString() => 'PeerInfo($deviceName, $os, :$port, ${trustState.name})';
}

/// A peer found on the network, plus the transport address needed to reach it.
class DiscoveredPeer {
  const DiscoveredPeer({
    required this.info,
    required this.address,
    required this.resolvedAt,
  });

  final PeerInfo info;

  /// Where to dial. May be discovered separately from [info] — mDNS gives us
  /// an address and a TXT record together, but the fallback paths may only
  /// give one of the two.
  final PeerAddress address;

  final DateTime resolvedAt;

  String get deviceId => info.deviceId;

  DiscoveredPeer copyWith({PeerInfo? info, PeerAddress? address}) =>
      DiscoveredPeer(
        info: info ?? this.info,
        address: address ?? this.address,
        resolvedAt: resolvedAt,
      );
}

/// How to reach a peer. Abstract so the same session logic works over a raw IP,
/// a `.local` hostname, or a browser-supplied endpoint.
class PeerAddress {
  const PeerAddress({required this.host, required this.port});

  /// An IPv4/IPv6 literal or a hostname. Prefer the literal when known:
  /// resolving `.local` requires working multicast, which is exactly the thing
  /// that may be broken.
  final String host;
  final int port;

  /// `scheme://host:port`, with IPv6 literals bracketed.
  Uri get uri {
    final needsBrackets = host.contains(':') && !host.startsWith('[');
    return Uri.parse('aero://${needsBrackets ? '[$host]' : host}:$port');
  }

  @override
  String toString() => '$host:$port';

  @override
  bool operator ==(Object other) =>
      other is PeerAddress && other.host == host && other.port == port;

  @override
  int get hashCode => Object.hash(host, port);
}

/// One file inside a transfer offer.
class FileEntry {
  const FileEntry({
    required this.id,
    required this.name,
    required this.size,
    this.relPath,
    this.sha256,
    this.mtimeMs,
  });

  factory FileEntry.fromJson(Map<String, dynamic> json) => FileEntry(
        id: json['id'] as String,
        name: json['name'] as String? ?? '',
        size: (json['size'] as num?)?.toInt() ?? 0,
        relPath: json['relPath'] as String?,
        sha256: json['sha256'] as String?,
        mtimeMs: (json['mtimeMs'] as num?)?.toInt(),
      );

  final String id;

  /// Basename shown to the user.
  final String name;

  /// Size in bytes. `int` is 64-bit on all supported platforms, so files well
  /// beyond 4 GiB are fine.
  final int size;

  /// Path relative to the transfer root, used to recreate folder structure.
  /// `null` means "at the root".
  final String? relPath;

  /// Lowercase hex SHA-256. `null` means "compute it on arrival"; the receiver
  /// then reports the digest it computed.
  final String? sha256;

  final int? mtimeMs;

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'size': size,
        if (relPath != null) 'relPath': relPath,
        if (sha256 != null) 'sha256': sha256,
        if (mtimeMs != null) 'mtimeMs': mtimeMs,
      };
}

/// The sender's proposal. Metadata only — no bytes have moved yet, so the
/// receiver can accept, partially accept, or reject before anything is written.
class Offer {
  const Offer({
    required this.sessionId,
    required this.files,
    required this.totalSize,
    this.folderName,
  });

  factory Offer.fromJson(Map<String, dynamic> json) => Offer(
        sessionId: json['sessionId'] as String,
        totalSize: (json['totalSize'] as num?)?.toInt() ?? 0,
        folderName: json['folderName'] as String?,
        files: ((json['files'] as List?) ?? const [])
            .map((e) => FileEntry.fromJson((e as Map).cast<String, dynamic>()))
            .toList(),
      );

  final String sessionId;
  final List<FileEntry> files;
  final int totalSize;

  /// When sending a folder, the top-level directory name to recreate.
  final String? folderName;

  Map<String, dynamic> toJson() => {
        'sessionId': sessionId,
        'totalSize': totalSize,
        if (folderName != null) 'folderName': folderName,
        'files': files.map((f) => f.toJson()).toList(),
      };
}

/// Why a file was refused. Surfaced verbatim in the UI so a partial accept
/// is explainable rather than mysterious.
enum RejectReason {
  noSpace,
  tooLarge,
  tooManyFiles,
  unsupportedName,
  duplicate,
  notAccepted,
  unknown;

  static RejectReason fromName(String name) {
    for (final r in RejectReason.values) {
      if (r.name == name) return r;
    }
    return RejectReason.unknown;
  }
}

/// Receiver's answer to an [Offer].
class OfferResponse {
  const OfferResponse({
    required this.sessionId,
    required this.accepted,
    this.rejected = const [],
    this.resume = const {},
    this.error,
  });

  factory OfferResponse.fromJson(Map<String, dynamic> json) => OfferResponse(
        sessionId: json['sessionId'] as String? ?? '',
        accepted: ((json['accepted'] as List?) ?? const [])
            .map((e) => e.toString())
            .toList(),
        rejected: ((json['rejected'] as List?) ?? const []).map((e) {
          final m = (e as Map).cast<String, dynamic>();
          return (m['id']?.toString() ?? '', RejectReason.fromName(m['reason']?.toString() ?? ''));
        }).toList(),
        resume: ((json['resume'] as Map?) ?? const {}).map(
          (k, v) => MapEntry(k.toString(), (v as num).toInt()),
        ),
        error: json['error'] as String?,
      );

  final String sessionId;
  final List<String> accepted;

  /// Pairs of (fileId, reason).
  final List<(String, RejectReason)> rejected;

  /// fileId -> bytes already stored, so a resumed transfer continues instead
  /// of restarting.
  final Map<String, int> resume;

  final String? error;

  bool get hasResume => resume.isNotEmpty;

  Map<String, dynamic> toJson() => {
        'sessionId': sessionId,
        'accepted': accepted,
        'rejected': [
          for (final (id, reason) in rejected) {'id': id, 'reason': reason.name},
        ],
        if (resume.isNotEmpty) 'resume': resume,
        if (error != null) 'error': error,
      };
}

/// Final integrity report from the sender. The receiver recomputes digests
/// from what is actually on disk rather than trusting these values.
class CompletionReport {
  const CompletionReport({
    required this.sessionId,
    required this.files,
    this.cancelled = false,
  });

  factory CompletionReport.fromJson(Map<String, dynamic> json) => CompletionReport(
        sessionId: json['sessionId'] as String? ?? '',
        cancelled: json['cancelled'] as bool? ?? false,
        files: ((json['files'] as List?) ?? const []).map((e) {
          final m = (e as Map).cast<String, dynamic>();
          return (m['id']?.toString() ?? '', m['sha256']?.toString() ?? '', (m['bytes'] as num?)?.toInt() ?? 0);
        }).toList(),
      );

  final String sessionId;

  /// Triples of (fileId, sha256Hex, bytes).
  final List<(String, String, int)> files;

  final bool cancelled;

  Map<String, dynamic> toJson() => {
        'sessionId': sessionId,
        'cancelled': cancelled,
        'files': [
          for (final (id, sha, bytes) in files)
            {'id': id, 'sha256': sha, 'bytes': bytes},
        ],
      };
}

/// Final receiver verdict.
class CompletionResult {
  const CompletionResult({required this.ok, this.failures = const []});

  factory CompletionResult.fromJson(Map<String, dynamic> json) => CompletionResult(
        ok: json['ok'] as bool? ?? false,
        failures: ((json['failures'] as List?) ?? const [])
            .map((e) => e.toString())
            .toList(),
      );

  final bool ok;
  final List<String> failures;

  Map<String, dynamic> toJson() => {'ok': ok, 'failures': failures};
}

/// Machine-readable error codes. Kept as strings on the wire so an old peer
/// sees an unknown code rather than crashing on a new enum value.
class ApiError {
  static const String sasMismatch = 'sas_mismatch';
  static const String sasExpired = 'sas_expired';

  /// The user looked at the code and said it does not match. Distinct from
  /// [sasMismatch], which means the codes disagree cryptographically — this is
  /// a human deciding the peer is not who it claims.
  static const String rejected = 'rejected';
  static const String tooManyAttempts = 'too_many_attempts';
  static const String badRequest = 'bad_request';
  static const String notPaired = 'not_paired';
  static const String noSpace = 'no_space';
  static const String tooLarge = 'too_large';
  static const String hashMismatch = 'hash_mismatch';
  static const String cancelled = 'cancelled';
  static const String unknownSession = 'unknown_session';
  static const String conflict = 'conflict';
  static const String internal = 'internal';
}

/// The short authentication string shown on both devices.
///
/// Two devices independently render the same six digits derived from their TLS
/// certificate fingerprints. Because the value is a truncation of a hash over a
/// 256-bit secret, the six digits carry no exploitable entropy: an attacker
/// cannot grind a code offline, and a man-in-the-middle — whose own key enters
/// the transcript — necessarily produces different digits.
class PairingProof {
  const PairingProof({
    required this.method,
    required this.value,
    required this.expiresAt,
  });

  /// Currently always [Crypto.pairingMethod]. A future SPAKE2 implementation
  /// slots in here without changing the protocol shape.
  final String method;

  /// Digits only, length [Pairing.codeDigits].
  final String value;

  final DateTime expiresAt;

  bool isExpired([DateTime? now]) =>
      (now ?? DateTime.now()).isAfter(expiresAt);

  /// Space-separated digits, e.g. `4 7 2 9 0 5`, for display.
  String get display => value.split('').join(' ');

  @override
  String toString() => 'PairingProof($method, $display)';
}

/// Response to a pairing attempt.
class PairingResult {
  const PairingResult({
    required this.paired,
    required this.trustState,
    this.error,
  });

  factory PairingResult.fromJson(Map<String, dynamic> json) => PairingResult(
        paired: json['paired'] as bool? ?? false,
        trustState: switch (json['trustState'] as String?) {
          'known' => TrustState.known,
          'identityConflict' => TrustState.identityConflict,
          _ => TrustState.unknown,
        },
        error: json['error'] as String?,
      );

  final bool paired;
  final TrustState trustState;
  final String? error;

  Map<String, dynamic> toJson() => {
        'paired': paired,
        'trustState': trustState.name,
        if (error != null) 'error': error,
      };
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

Uint8List? _tryDecode(String? s) {
  if (s == null || s.isEmpty) return null;
  try {
    return base64Decode(s);
  } on FormatException {
    return null;
  }
}

/// FIPS 180-4 SHA-256 for the short, fixed-size inputs in this file.
///
/// Implemented directly rather than via `package:cryptography` because the
/// only caller needs it *synchronously* (inside `toTxt()`), and `Hash.hash()`
/// returns a Future. The file-digest paths use `cryptography` instead, where
/// the streaming API and native acceleration matter.
Uint8List _sha256(List<int> message) {
  const List<int> k = [
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

  final h = Uint32List.fromList([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  final bitLen = message.length * 8;
  final padded = <int>[...message, 0x80];
  while (padded.length % 64 != 56) {
    padded.add(0);
  }
  for (var i = 7; i >= 0; i--) {
    padded.add((bitLen >> (i * 8)) & 0xff);
  }

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
      final temp1 = (hh + s1 + ch + k[i] + w[i]) & 0xffffffff;
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

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;
