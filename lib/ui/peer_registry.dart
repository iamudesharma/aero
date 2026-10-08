/// Holds the live peer list, deduplicated and expired.
///
/// Discovery emits every resolve it sees, including repeats and our own
/// advertisement. Keeping that raw stream straight into a widget would cause
/// rebuild storms and would show the device itself as a peer, so this class
/// maintains the canonical list instead.
///
/// Expiry matters as much as deduplication: a peer that powered off never sends
/// a goodbye packet, so without a TTL its row would sit in the UI forever.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../core/constants.dart';
import '../core/contracts.dart';
import '../core/models.dart';
import 'device_info.dart' show currentOs, kAppVersion, platformOsVersion;

/// How long a peer may go unheard before it is dropped.
const Duration kPeerTtl = Duration(seconds: 75);

/// Builds a fresh `PeerInfo` for this device.
///
/// [nonce] must be freshly generated per session by the caller, not per call.
PeerInfo buildSelfInfo({
  required String deviceId,
  required String deviceName,
  required String publicKey,
  required String nonce,
  required int port,
}) =>
    PeerInfo(
      deviceId: deviceId,
      deviceName: deviceName,
      os: currentOsForRegistry(),
      osVersion: platformOsVersionForRegistry(),
      appVersion: kAppVersionForRegistry,
      publicKey: publicKey,
      protocolVersion: kProtocolVersionForRegistry,
      capabilities: const {
        Capability.send,
        Capability.receive,
        Capability.multiFile,
        Capability.folder,
        Capability.resume,
      },
      nonce: nonce,
      port: port,
    );

// Injected indirection keeps this file unit-testable without dragging in
// dart:io platform checks.
AeroOs Function() currentOsForRegistry = currentOs;
String Function() platformOsVersionForRegistry = platformOsVersion;
const String kAppVersionForRegistry = kAppVersion;
const int kProtocolVersionForRegistry = kProtocolVersion;

class PeerRegistry extends ChangeNotifier {
  PeerRegistry({Duration? ttl, DateTime Function()? clock})
      : _ttl = ttl ?? kPeerTtl,
        _now = clock ?? DateTime.now;

  final Duration _ttl;
  final DateTime Function() _now;

  final Map<String, DiscoveredPeer> _peers = {};
  StreamSubscription<DiscoveredPeer>? _sub;
  Timer? _sweepTimer;

  /// Peers ordered most-recently-seen first.
  List<DiscoveredPeer> get peers {
    final list = _peers.values.toList()
      ..sort((a, b) => b.resolvedAt.compareTo(a.resolvedAt));
    return List.unmodifiable(list);
  }

  int get count => _peers.length;

  DiscoveredPeer? byId(String deviceId) => _peers[deviceId];

  /// Begin tracking [source], ignoring records that name this device.
  ///
  /// [selfDeviceId] is required because mDNS always resolves our own
  /// advertisement; without this filter the user sees their own machine in the
  /// list and can try to pair with it.
  void attach(DiscoveryService source, {required String selfDeviceId}) {
    _sub?.cancel();
    _sub = source.peers.listen((peer) => _ingest(peer, selfDeviceId));

    // Sweep on a timer rather than only on incoming records, so a peer that
    // disappears silently is still removed from the list.
    _sweepTimer?.cancel();
    _sweepTimer = Timer.periodic(const Duration(seconds: 5), (_) => _sweep());
  }

  void _ingest(DiscoveredPeer peer, String selfDeviceId) {
    final id = peer.deviceId;
    if (id.isEmpty || id == selfDeviceId) return;

    final existing = _peers[id];
    // A peer may resolve at a new address (DHCP lease change, Wi-Fi switch).
    // Prefer the newer record but keep the original `resolvedAt` only if the
    // address is unchanged, so the TTL measures "last heard from" not
    // "first seen".
    final isNewAddress = existing == null || existing.address != peer.address;
    _peers[id] = DiscoveredPeer(
      info: peer.info,
      address: peer.address,
      resolvedAt: isNewAddress ? _now() : existing.resolvedAt,
    );
    notifyListeners();
  }

  void _sweep() {
    final cutoff = _now().subtract(_ttl);
    final expired = _peers.entries
        .where((e) => e.value.resolvedAt.isBefore(cutoff))
        .map((e) => e.key)
        .toList();
    if (expired.isEmpty) return;
    for (final id in expired) {
      _peers.remove(id);
    }
    notifyListeners();
  }

  /// Merge in the result of the authenticated `GET /v1/info` handshake, which
  /// carries the real public key and a live nonce — richer and more trustworthy
  /// than the TXT record, which only carries a key hash.
  void enrich(String deviceId, PeerInfo authoritative) {
    final existing = _peers[deviceId];
    if (existing == null) return;
    _peers[deviceId] = existing.copyWith(
      info: PeerInfo(
        deviceId: authoritative.deviceId,
        deviceName: authoritative.deviceName,
        os: authoritative.os,
        osVersion: authoritative.osVersion,
        appVersion: authoritative.appVersion,
        publicKey: authoritative.publicKey,
        protocolVersion: authoritative.protocolVersion,
        capabilities: authoritative.capabilities,
        nonce: authoritative.nonce,
        port: existing.address.port,
        trustState: authoritative.trustState,
        // Carried across from the mDNS record: this is the only point at which
        // the pre-pairing key hash is available, so overwriting it with an
        // empty string would lose the ability to flag a changed key.
        publicKeyHash: existing.info.publicKeyHash,
      ),
    );
    notifyListeners();
  }

  void clear() {
    if (_peers.isEmpty) return;
    _peers.clear();
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    _sweepTimer?.cancel();
    super.dispose();
  }
}