/// Which transport path Aero should use, and the observable decision that
/// picks it.
///
/// # Why this exists before any fallback is implemented
///
/// The fallback hierarchy (shared LAN -> Android LocalOnlyHotspot -> BLE
/// rendezvous -> manual/QR) is a plan, not code. But the *decision point* has to
/// exist from the start, for two reasons:
///
///   1. It is the seam the later tiers plug into. Adding a tier later is a new
///      enum value plus a branch, not a rewrite of `AppCoordinator`.
///   2. It makes the choice observable now, while only Tier 0 is real. When a
///      real-device run later picks the wrong path, the log already says why.
///
/// Phase 0 implements Tier 0 only. [LinkStrategy.select] is deliberately
/// incapable of returning anything else yet - see [_LinkStrategyPhase0].
library;

import '../logging.dart';
import 'network_context.dart';

/// The ordered fallback ladder. Ordered by preference: LOWER ordinal is tried
/// first, and the ordering is the contract.
enum TransportTier {
  /// Both devices already share a Wi-Fi/Ethernet subnet. mDNS + TLS/TCP.
  /// Fastest, verified working, and the default.
  sharedLan(0, 'shared LAN'),

  /// The phone creates a LocalOnlyHotspot and the Mac joins it. Same protocol,
  /// a different way of getting onto a common subnet.
  hotspot(1, 'Android local-only hotspot'),

  /// No shared IP link and no hotspot: use BLE purely to rendezvous and hand
  /// off an endpoint (SSID/PSK or IP:port). Never carries file bytes.
  bleRendezvous(2, 'BLE rendezvous'),

  /// Last resort: the user joins manually or scans a QR code. Depends on
  /// neither mDNS nor BLE.
  manual(3, 'manual pairing');

  const TransportTier(this.rank, this.label);

  /// Preference order; lower wins.
  final int rank;

  /// Human-readable name for the UI.
  final String label;

  /// True for tiers that use the normal mDNS + TCP/TLS path once a shared
  /// subnet exists. Used to keep the transport itself unchanged.
  bool get usesSharedLanTransport => this == sharedLan || this == hotspot;
}

/// Why a tier was selected.
///
/// The identifiers are stable strings on purpose: they are the thing a real
/// device run is grepped for, and the thing the diagnostics panel renders. The
/// set grows as later tiers land; Phase 0 defines only the ones it can produce
/// plus the two the user asked for that describe *why Tier 0 was not chosen*
/// when a fallback would be needed.
enum TierReason {
  /// A usable non-loopback interface exists, so try the shared LAN first.
  lanAvailable('LAN_AVAILABLE'),

  /// The LAN path is running but has found no peers. Tier 0 is still the right
  /// choice - the user may simply not have the other app open - so this does
  /// NOT trigger a fallback by itself. It is the signal a fallback would act on.
  noReachablePeers('NO_REACHABLE_PEERS'),

  /// Only loopback is present: no shared subnet exists to discover peers on.
  /// This is the condition the hotspot tier exists to fix.
  noSharedSubnet('NO_SHARED_SUBNET'),

  /// An interface exists but has no usable address yet (no DHCP lease, captive
  /// portal). Waiting briefly is more likely to help than starting a hotspot.
  noUsableInterface('NO_USABLE_INTERFACE'),

  /// Interface enumeration failed. Reported honestly rather than guessed at.
  enumerationFailed('ENUMERATION_FAILED'),

  /// mDNS itself is unavailable (denied local-network permission, no browser).
  /// A fallback may still work even though discovery cannot, so this is
  /// distinct from the network conditions above.
  mdnsUnavailable('MDNS_UNAVAILABLE'),

  /// A future fallback tier was required but is not implemented in this build.
  /// Emitted by the selector so the gap is visible instead of silent.
  hotspotRequired('HOTSPOT_REQUIRED'),

  /// No shared subnet, no hotspot hosting, but BLE is available: rendezvous
  /// over Bluetooth to hand over an endpoint or hotspot credentials.
  bleRendezvous('BLE_RENDEZVOUS'),

  /// Nothing automated is left: no shared subnet, no hotspot hosting, and no
  /// BLE. The user must exchange a connection string by hand. Always available,
  /// because it needs no radio at all.
  manualRequired('MANUAL_REQUIRED');

  const TierReason(this.id);

  /// Stable identifier for logs and diagnostics.
  final String id;

  @override
  String toString() => id;
}

/// The outcome of a tier decision: which tier, and why.
class TierDecision {
  const TierDecision({
    required this.tier,
    required this.reason,
    this.detail = '',
  });

  final TransportTier tier;
  final TierReason reason;

  /// Optional human-readable elaboration for the diagnostics panel.
  final String detail;

  /// True when the selected tier is the currently-implemented one.
  bool get isSupported => tier == TransportTier.sharedLan;

  /// A line suitable for the diagnostics panel.
  String get summary => detail.isEmpty
      ? '${tier.label}: ${reason.id}'
      : '${tier.label}: ${reason.id} — $detail';

  @override
  String toString() => 'TierDecision(${tier.name}, ${reason.id})';
}

/// Chooses a [TransportTier] from the observed [NetworkContext].
///
/// An interface rather than a bare function so tests can substitute a
/// deterministic selector, and so later tiers can be swapped in without touching
/// any call site.
abstract class LinkStrategy {
  /// Pick a tier. Must not throw: a selector that can fail is a selector that
  /// can take the app down at startup.
  TierDecision select(NetworkContext context);
}

/// Phase 0 selector: always Tier 0, with the reason recorded.
///
/// This is deliberately a *real* decision rather than a hardcoded constant. It
/// examines [NetworkContext] and reports the reason honestly - including when
/// the LAN is absent, in which case it still returns [TransportTier.sharedLan]
/// (because nothing else exists yet) but flags [TierReason.hotspotRequired] so
/// the missing fallback is visible in the log and the UI rather than hidden
/// behind a cheerful "shared LAN" line.
class Phase0LinkStrategy implements LinkStrategy {
  const Phase0LinkStrategy();

  @override
  TierDecision select(NetworkContext context) {
    switch (context.reason) {
      case NetworkContextReason.lanAvailable:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.lanAvailable,
          detail: 'interfaces: '
              '${context.lanInterfaces.map((i) => i.name).join(', ')}',
        );

      case NetworkContextReason.noSharedSubnet:
        // No subnet and no fallback built yet: stay on Tier 0 (the only real
        // transport) but make the gap explicit. The log line is the thing a
        // real-device run will show, and it names the tier that is missing.
        _noteMissingFallback(TierReason.noSharedSubnet);
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.hotspotRequired,
          detail: 'no shared subnet; the hotspot and BLE tiers are not built '
              'yet, so discovery will find nothing',
        );

      case NetworkContextReason.noUsableInterface:
        _noteMissingFallback(TierReason.noUsableInterface);
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.noUsableInterface,
          detail: 'an interface exists but has no usable address yet; waiting '
              'for a lease rather than starting a fallback',
        );

      case NetworkContextReason.enumerationFailed:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.enumerationFailed,
          detail: context.error?.toString() ?? '',
        );
    }
  }

  void _noteMissingFallback(TierReason observed) {
    coreLog.info(
      'transport tier: $observed observed, but no offline fallback is '
      'implemented yet; continuing on the shared-LAN path',
    );
  }
}

/// The Phase 1 selector: Tier 0 when the LAN is usable, Tier 1 when it is not
/// and this device can host a hotspot.
///
/// # The two rules that must not blur
///
///   * [TierReason.noReachablePeers] never selects a fallback. "Nobody else has
///     the app open" is the normal state on a perfectly good network, and
///     silently standing up a hotspot because a scan was empty would be both
///     surprising and power-hungry.
///   * [TierReason.noSharedSubnet] selects [TransportTier.hotspot] only when
///     hosting is actually possible; otherwise it falls back to the Phase 0
///     behaviour of staying on Tier 0 and reporting the gap.
///
/// The decision is a *recommendation*. Starting a hotspot is user-driven (see
/// `AppCoordinator.beginDirectTransfer`), so this only labels the state - it
/// never turns a radio on.
class Phase1LinkStrategy implements LinkStrategy {
  const Phase1LinkStrategy({required this.canHostHotspot});

  /// Whether this device can create a hotspot right now. Injected rather than
  /// queried so the selector stays pure and testable.
  final bool canHostHotspot;

  @override
  TierDecision select(NetworkContext context) {
    switch (context.reason) {
      case NetworkContextReason.lanAvailable:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.lanAvailable,
          detail: 'interfaces: '
              '${context.lanInterfaces.map((i) => i.name).join(', ')}',
        );

      case NetworkContextReason.noSharedSubnet:
        if (canHostHotspot) {
          return const TierDecision(
            tier: TransportTier.hotspot,
            reason: TierReason.hotspotRequired,
            detail: 'no shared subnet; a direct-transfer hotspot can provide '
                'one. Starting it is the user\'s choice.',
          );
        }
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.hotspotRequired,
          detail: 'no shared subnet, and this device cannot host a hotspot; '
              'the other device must start one',
        );

      case NetworkContextReason.noUsableInterface:
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.noUsableInterface,
          detail: 'an interface exists but has no usable address yet; waiting '
              'for a lease rather than starting a fallback',
        );

      case NetworkContextReason.enumerationFailed:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.enumerationFailed,
          detail: context.error?.toString() ?? '',
        );
    }
  }
}

/// The Phase 2 selector: Phase 1, plus a BLE rendezvous tier.
///
/// # The ladder
///
///   * a usable LAN always wins (`sharedLan`);
///   * no subnet + this device can host -> `hotspot`;
///   * no subnet + cannot host + BLE available -> `bleRendezvous`;
///   * no subnet + cannot host + no BLE -> the honest `hotspotRequired` gap.
///
/// # The rule that still must not blur
///
/// [TierReason.noReachablePeers] **never** selects a fallback, at any phase. An
/// empty peer list on a perfectly good network is the normal state; standing up
/// a hotspot or a BLE advertisement because a scan came back empty would be
/// surprising and power-hungry.
///
/// Like Phase 1, this only *labels* the right path. Every fallback is started by
/// the user (see `AppCoordinator.beginDirectTransfer`).
class Phase2LinkStrategy implements LinkStrategy {
  const Phase2LinkStrategy({
    required this.canHostHotspot,
    required this.canBleRendezvous,
  });

  /// Whether this device can create a hotspot.
  final bool canHostHotspot;

  /// Whether this device can take part in a BLE rendezvous (advertise or scan).
  final bool canBleRendezvous;

  @override
  TierDecision select(NetworkContext context) {
    switch (context.reason) {
      case NetworkContextReason.lanAvailable:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.lanAvailable,
          detail: 'interfaces: '
              '${context.lanInterfaces.map((i) => i.name).join(', ')}',
        );

      case NetworkContextReason.noSharedSubnet:
        if (canHostHotspot) {
          return const TierDecision(
            tier: TransportTier.hotspot,
            reason: TierReason.hotspotRequired,
            detail: 'no shared subnet; a direct-transfer hotspot can provide '
                'one. Starting it is the user\'s choice.',
          );
        }
        if (canBleRendezvous) {
          return const TierDecision(
            tier: TransportTier.bleRendezvous,
            reason: TierReason.bleRendezvous,
            detail: 'no shared subnet and this device cannot host; use BLE to '
                'rendezvous and hand over an endpoint or hotspot credentials.',
          );
        }
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.hotspotRequired,
          detail: 'no shared subnet, and this device can neither host a hotspot '
              'nor use BLE; the other device must provide the link',
        );

      case NetworkContextReason.noUsableInterface:
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.noUsableInterface,
          detail: 'an interface exists but has no usable address yet; waiting '
              'for a lease rather than starting a fallback',
        );

      case NetworkContextReason.enumerationFailed:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.enumerationFailed,
          detail: context.error?.toString() ?? '',
        );
    }
  }
}

/// The Phase 3 selector: the complete ladder, ending in manual pairing.
///
///   * a usable LAN always wins (`sharedLan`);
///   * no subnet + this device can host -> `hotspot`;
///   * no subnet + cannot host + BLE -> `bleRendezvous`;
///   * no subnet + cannot host + no BLE -> `manual`.
///
/// # Why manual is unconditional
///
/// Unlike every earlier tier, [TransportTier.manual] has no capability
/// precondition: it needs no radio, no multicast, and no permission - only the
/// user's eyes and fingers. So the ladder always has a bottom rung, and the
/// selector can never return "there is nothing we can do". That matters most on
/// the vendor ROMs that block BLE and multicast at once, which is precisely the
/// case the earlier phases could not serve.
///
/// # The rule that still must not blur
///
/// [TierReason.noReachablePeers] **never** selects a fallback. An empty peer list
/// on a good network is the normal state, and prompting for a manual connection
/// string because a scan was empty would be wrong.
class Phase3LinkStrategy implements LinkStrategy {
  const Phase3LinkStrategy({
    required this.canHostHotspot,
    required this.canBleRendezvous,
  });

  /// Whether this device can create a hotspot.
  final bool canHostHotspot;

  /// Whether this device can take part in a BLE rendezvous (advertise or scan).
  final bool canBleRendezvous;

  @override
  TierDecision select(NetworkContext context) {
    switch (context.reason) {
      case NetworkContextReason.lanAvailable:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.lanAvailable,
          detail: 'interfaces: '
              '${context.lanInterfaces.map((i) => i.name).join(', ')}',
        );

      case NetworkContextReason.noSharedSubnet:
        if (canHostHotspot) {
          return const TierDecision(
            tier: TransportTier.hotspot,
            reason: TierReason.hotspotRequired,
            detail: 'no shared subnet; a direct-transfer hotspot can provide '
                'one. Starting it is the user\'s choice.',
          );
        }
        if (canBleRendezvous) {
          return const TierDecision(
            tier: TransportTier.bleRendezvous,
            reason: TierReason.bleRendezvous,
            detail: 'no shared subnet and this device cannot host; use BLE to '
                'rendezvous and hand over an endpoint or hotspot credentials.',
          );
        }
        return const TierDecision(
          tier: TransportTier.manual,
          reason: TierReason.manualRequired,
          detail: 'no shared subnet, no hotspot hosting, and no BLE; exchange '
              'a connection string by hand.',
        );

      case NetworkContextReason.noUsableInterface:
        return const TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.noUsableInterface,
          detail: 'an interface exists but has no usable address yet; waiting '
              'for a lease rather than starting a fallback',
        );

      case NetworkContextReason.enumerationFailed:
        return TierDecision(
          tier: TransportTier.sharedLan,
          reason: TierReason.enumerationFailed,
          detail: context.error?.toString() ?? '',
        );
    }
  }
}

/// A strategy that reports the state of discovery as well as the network.
///
/// Kept separate from [LinkStrategy] so that the network-only decision stays
/// pure and trivially testable. `AppCoordinator` uses this to turn a live
/// discovery failure into [TierReason.mdnsUnavailable] for diagnostics.
TierReason mdnsUnavailableReason(String? discoveryProblem, int peerCount) {
  if (discoveryProblem != null) return TierReason.mdnsUnavailable;
  if (peerCount == 0) return TierReason.noReachablePeers;
  return TierReason.lanAvailable;
}
