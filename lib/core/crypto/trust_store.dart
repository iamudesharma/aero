/// Durable trust-on-first-use store for paired devices.
///
/// This class owns persistence; code derivation and rate limiting belong to
/// [SasPairingAuthority]. See the composition note below.
///
/// ## Composition, not inheritance
///
/// `PairingAuthority` bundles two unrelated responsibilities — "derive the six
/// digits" and "remember who I have paired with" — behind one interface, so
/// something has to implement all five methods. Making `TrustStore` a subclass
/// of `SasPairingAuthority` would inherit the derivation logic it does not own
/// and would make it impossible to swap either half independently (say, to add
/// an SPAKE2 derivation later, or a platform keychain-backed trust store).
/// Holding a [SasPairingAuthority] as a field keeps the two halves separable
/// and lets tests inject a fake clock into the pairing half.
///
/// ## Trust decisions
///
/// * No entry for the device id -> [TrustState.unknown]. The user must confirm a
///   code.
/// * Entry whose key matches -> [TrustState.known]. Skip the code.
/// * Entry for the same device id with a *different* key ->
///   [TrustState.identityConflict]. Either an impostor on the LAN, or the peer
///   was reinstalled and lost its identity. These are indistinguishable from
///   here, and the safe answer to both is the same: do not trust, require the
///   code, and tell the user. Silently preferring the new key would let anyone
///   who knows a device id hijack an existing pairing by simply announcing a
///   different key.
library;

import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import '../constants.dart';
import '../contracts.dart';
import '../logging.dart';
import '../models.dart';
import 'sas_pairing.dart';

/// One pinned peer as stored on disk.
class TrustedPeer {
  const TrustedPeer({
    required this.deviceId,
    required this.publicKey,
    this.alias,
    required this.lastSeenMs,
  });

  factory TrustedPeer.fromJson(Map<String, dynamic> json) => TrustedPeer(
        deviceId: json['deviceId'] as String? ?? '',
        publicKey: json['publicKey'] as String? ?? '',
        alias: json['alias'] as String?,
        lastSeenMs: (json['lastSeenMs'] as num?)?.toInt() ?? 0,
      );

  final String deviceId;
  final String publicKey;

  /// Optional user-supplied nickname. The pairing API cannot set one yet; the UI
  /// can write it into the file directly.
  final String? alias;

  final int lastSeenMs;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'deviceId': deviceId,
        'publicKey': publicKey,
        if (alias != null) 'alias': alias,
        'lastSeenMs': lastSeenMs,
      };
}

/// Persists pinned peers to `<app support>/trusted_peers.json`.
class TrustStore implements PairingAuthority {
  TrustStore({
    Directory? directory,
    SasPairingAuthority? pairing,
    DateTime Function()? clock,
  })  : _directoryOverride = directory,
        pairing = pairing ??
            SasPairingAuthority(clock: clock),
        _clock = clock ?? DateTime.now;

  /// File name inside the app support directory.
  static const String fileName = 'trusted_peers.json';

  /// Bumped only if the on-disk shape changes incompatibly.
  static const int _formatVersion = 1;

  final Directory? _directoryOverride;
  final SasPairingAuthority pairing;
  final DateTime Function() _clock;

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  /// The app support directory, or the override supplied at construction.
  ///
  /// Resolved lazily on every call rather than cached: `path_provider` is a
  /// platform channel, so touching it in a constructor would make the class
  /// untestable, and caching would freeze the wrong value in tests.
  Future<Directory> resolveDirectory() async {
    final dir = _directoryOverride ?? await getApplicationSupportDirectory();
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir;
  }

  Future<File> _file() async {
    final dir = await resolveDirectory();
    return File('${dir.path}${Platform.pathSeparator}$fileName');
  }

  /// Every pinned peer. A missing or corrupt file reads as "none paired".
  ///
  /// Never throws. A trust file that cannot be parsed means the user re-confirms
  /// a pairing code once; refusing to start the app would mean they cannot pair
  /// at all.
  ///
  /// Always returns a growable list: callers such as [rememberPeer] edit the
  /// result in place, and handing back a `const` empty list here made the very
  /// first `rememberPeer` on a fresh store throw.
  Future<List<TrustedPeer>> loadPeers() async {
    try {
      final file = await _file();
      if (!await file.exists()) return <TrustedPeer>[];
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map<String, dynamic>) return <TrustedPeer>[];
      final raw = decoded['peers'];
      if (raw is! List) return <TrustedPeer>[];
      final peers = <TrustedPeer>[];
      for (final entry in raw) {
        if (entry is! Map) continue;
        final peer = TrustedPeer.fromJson(entry.cast<String, dynamic>());
        // A row without a device id or key is useless and would shadow a valid
        // one, so drop it rather than letting it match everything.
        if (peer.deviceId.isEmpty || peer.publicKey.isEmpty) continue;
        peers.add(peer);
      }
      return peers;
    } catch (error, stack) {
      coreLog.warning('$fileName is unreadable; treating as no peers', error, stack);
      return <TrustedPeer>[];
    }
  }

  Future<void> _save(List<TrustedPeer> peers) async {
    final file = await _file();
    final payload = jsonEncode(<String, dynamic>{
      'version': _formatVersion,
      'peers': peers.map((p) => p.toJson()).toList(),
    });
    await _atomicWrite(file, '$payload\n');
  }

  // -------------------------------------------------------------------------
  // PairingAuthority
  // -------------------------------------------------------------------------

  @override
  PairingProof deriveProof({
    required String localFingerprint,
    required String remoteFingerprint,
    required String nonce,
    String method = Crypto.pairingMethod,
  }) =>
      pairing.deriveProof(
        localFingerprint: localFingerprint,
        remoteFingerprint: remoteFingerprint,
        nonce: nonce,
        method: method,
      );

  @override
  bool verifyProof(PairingProof presented, PairingProof expected) =>
      pairing.verifyProof(presented, expected);

  @override
  bool isRateLimited(String deviceId) => pairing.isRateLimited(deviceId);

  @override
  void recordFailure(String deviceId) => pairing.recordFailure(deviceId);

  /// Pins (or re-pins) [deviceId] to [publicKey].
  ///
  /// [alias] is accepted for callers that have a nickname; the frozen
  /// `PairingAuthority` signature does not carry one, and widening a parameter
  /// with a default is legal in Dart, so the interface is satisfied without
  /// being edited.
  @override
  Future<void> rememberPeer({
    required String deviceId,
    required String publicKey,
    String? alias,
  }) async {
    final peers = await loadPeers();
    final index = peers.indexWhere((p) => p.deviceId == deviceId);
    final peer = TrustedPeer(
      deviceId: deviceId,
      publicKey: publicKey,
      alias: alias ?? (index >= 0 ? peers[index].alias : null),
      lastSeenMs: _clock().millisecondsSinceEpoch,
    );
    if (index >= 0) {
      peers[index] = peer;
    } else {
      peers.add(peer);
    }
    await _save(peers);
    coreLog.info('remembered peer $deviceId');
  }

  @override
  Future<TrustState> lookupTrust({
    required String deviceId,
    required String publicKey,
  }) async {
    final peers = await loadPeers();
    final matches = peers.where((p) => p.deviceId == deviceId);
    if (matches.isEmpty) return TrustState.unknown;

    // Same device id, different key: impersonation or a reinstall. Never trust
    // it, and never quietly overwrite the pin either — the user may still want
    // the old device after an attacker shows up.
    if (matches.any((p) => p.publicKey != publicKey)) {
      coreLog.warning(
        'identity conflict for $deviceId: stored key does not match presented',
      );
      return TrustState.identityConflict;
    }
    return TrustState.known;
  }

  @override
  Future<void> forgetPeer(String deviceId) async {
    final peers = await loadPeers();
    final kept = peers.where((p) => p.deviceId != deviceId).toList(growable: true);
    if (kept.length == peers.length) return;
    await _save(kept);
    pairing.resetFailures(deviceId);
    coreLog.info('forgot peer $deviceId');
  }
}

/// Write to a sibling `.tmp` then `rename` over the target.
///
/// `rename` is atomic within a directory on every filesystem this app targets,
/// so a crash mid-write leaves either the old file or the new one — never a
/// truncated JSON document. Without this, losing power during a save could drop
/// a user's entire pairing history, which is unrecoverable from their side.
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