/// What the local network looks like right now, so a [LinkStrategy] can decide
/// whether the shared-LAN path is viable before touching discovery.
///
/// # Why this is a *probe* and not a fact
///
/// Everything here is a snapshot of a moving target. Wi-Fi roams, a phone walks
/// out of range, a VPN comes up, a router's guest network turns on client
/// isolation. So the probe answers exactly one question - "is there anything
/// worth *trying*?" - and never "will a transfer succeed?". The transport is
/// still the only thing that knows whether a peer is reachable; this layer only
/// avoids pointless work and, more importantly, produces the machine-readable
/// reason a tier was chosen that the diagnostics panel shows.
///
/// # Tiering and the absence of a shared link
///
/// The offline fallback (Android LocalOnlyHotspot) exists for the case where
/// there is no shared subnet. That is not the same as "no interface": a phone on
/// cellular has an interface and a default route, but no LAN anyone else can
/// reach. [hasSharedLanCandidate] encodes that distinction, because getting it
/// wrong in either direction is costly - a false negative makes the app offer a
/// fallback while the LAN is fine, and a false positive makes it silently wait
/// for peers that can never appear.
library;

import 'dart:io';

import '../logging.dart';

/// What kind of link an interface carries.
///
/// This matters because "has a dialable address" is **not** the same as "another
/// device can reach us on it". A phone on cellular has `rmnet_data1` with a real
/// address, but it sits behind the carrier's NAT: nobody can dial it, and mDNS
/// cannot cross it. Counting that as a shared LAN would make the app claim the
/// LAN is fine while the peer list stays empty forever - the exact confusion the
/// tier ladder exists to remove.
enum InterfaceKind {
  /// Wi-Fi. The canonical shared LAN.
  wifi,

  /// Wired Ethernet. Also a shared LAN.
  ethernet,

  /// Cellular / mobile data. **Never** a peer-to-peer link: carrier NAT, and no
  /// multicast. Excluded from LAN candidates.
  cellular,

  /// A tunnel (VPN, WireGuard, utun). Excluded: the peer is not on it, and a VPN
  /// that does route the subnet often blocks the peer traffic anyway.
  vpn,

  /// Loopback.
  loopback,

  /// Anything we cannot classify. Treated **as a LAN candidate** on purpose: the
  /// cost of a false positive is one doomed dial, while a false negative could
  /// hide a real network on an OS whose naming we did not anticipate.
  other;

  /// Whether a peer could plausibly share a subnet with us over this link.
  bool get isSharedLinkCandidate =>
      this == wifi || this == ethernet || this == other;
}

/// A network interface that could plausibly carry a peer-to-peer transfer.
///
/// Deliberately a plain value: this is passed around, compared in tests, and
/// never mutated.
class NetworkInterfaceSummary {
  const NetworkInterfaceSummary({
    required this.name,
    required this.addresses,
    required this.isLoopback,
    this.kind = InterfaceKind.other,
  });

  final String name;

  /// Dialable addresses on this interface, as strings. Empty when the interface
  /// exists but has no address we could put in a peer record.
  final List<String> addresses;

  final bool isLoopback;

  /// What kind of link this is; see [InterfaceKind].
  final InterfaceKind kind;

  /// True when this interface carries at least one address a peer could dial.
  bool get isUsable => addresses.isNotEmpty;

  /// True when this is a usable link a peer could actually share.
  ///
  /// Both halves are required: a reachable address *and* a link type that can
  /// carry peer traffic. This is the predicate every caller should use - [isUsable]
  /// alone would count cellular.
  bool get isLanCandidate =>
      isUsable && !isLoopback && kind.isSharedLinkCandidate;

  @override
  String toString() =>
      '$name(${isLoopback ? 'loopback' : kind.name}:${addresses.join('/')})';
}

/// Classify an interface by its platform name.
///
/// Heuristic by necessity: `dart:io` exposes only a name and addresses, with no
/// link type. The names below are the conventional ones across Linux, macOS,
/// iOS, Android and Windows, and the fallback ([InterfaceKind.other]) is treated
/// as a LAN candidate rather than excluded, so an unanticipated name degrades to
/// "try it and see" instead of "silently ignore a real network".
InterfaceKind classifyInterface(String name) {
  final n = name.toLowerCase();

  // Loopback: `lo`, `lo0`, `wlan0:1` style aliases are not loopback, but the
  // bare forms are.
  if (n == 'lo' || n == 'lo0' || n.startsWith('lo') && !n.startsWith('ll')) {
    return InterfaceKind.loopback;
  }

  // Cellular. `rmnet*` (Qualcomm), `ccmni*` (MediaTek), `pdp*`, `wwan*`, `enp*`
  // is Ethernet and is handled below. `p2p` is Wi-Fi Direct and is a real (if
  // currently unused) link, so it is left to `other`.
  if (n.startsWith('rmnet') ||
      n.startsWith('ccmni') ||
      n.startsWith('pdp') ||
      n.startsWith('wwan') ||
      n.startsWith('rmnet_data')) {
    return InterfaceKind.cellular;
  }

  // Tunnels. `utun*` (Darwin), `tun*`/`tap*` (Linux), `wg*`, `ipsec*`, `ppp*`.
  if (n.startsWith('utun') ||
      n.startsWith('tun') ||
      n.startsWith('tap') ||
      n.startsWith('wg') ||
      n.startsWith('ipsec') ||
      n.startsWith('ppp')) {
    return InterfaceKind.vpn;
  }

  // Wi-Fi. `en0` on macOS/iOS is usually Wi-Fi but not always, so it is not
  // forced here; the mobile names are unambiguous.
  if (n.startsWith('wlan') || n.startsWith('wl') || n.startsWith('ap')) {
    return InterfaceKind.wifi;
  }

  // Ethernet: `en*` (Darwin), `eth*`, `enp*`/`eno*`/`enx*` (Linux predictable
  // names), `veth*`, and Windows' `ethernet`.
  if (n.startsWith('en') ||
      n.startsWith('eth') ||
      n.startsWith('veth') ||
      n.contains('ethernet')) {
    return InterfaceKind.ethernet;
  }

  return InterfaceKind.other;
}

/// Why a shared LAN is, or is not, worth trying.
///
/// These strings are the observable contract the user asked for: they go to the
/// log *and* to the diagnostics panel, so a real-device run explains itself
/// without a debugger. Treat the values as stable identifiers, not prose.
enum NetworkContextReason {
  /// At least one non-loopback interface carries a dialable address.
  lanAvailable('LAN_AVAILABLE'),

  /// The device has only loopback. Nothing can reach it, and it can reach
  /// nothing: there is no link at all, only a fallback could help.
  noSharedSubnet('NO_SHARED_SUBNET'),

  /// Interfaces exist but none carries a usable address - the classic
  /// "connected to Wi-Fi, no DHCP lease yet" or "captive portal, no route".
  noUsableInterface('NO_USABLE_INTERFACE'),

  /// Interface enumeration failed outright (a hardened platform, a sandbox that
  /// refuses the call). Not the same as having none, so it is reported
  /// separately rather than being folded into [noSharedSubnet].
  enumerationFailed('ENUMERATION_FAILED');

  const NetworkContextReason(this.id);

  /// Stable identifier for logs and diagnostics.
  final String id;

  @override
  String toString() => id;
}

/// A point-in-time view of the device's network interfaces.
class NetworkContext {
  const NetworkContext({
    required this.interfaces,
    required this.reason,
    this.error,
  });

  /// Every interface we saw, loopback included, for diagnostics. A peer list
  /// that is empty because the only interface is `lo0` is a very different bug
  /// from one that is empty because nobody else is running the app.
  final List<NetworkInterfaceSummary> interfaces;

  final NetworkContextReason reason;

  /// The exception from a failed enumeration, for the diagnostics panel.
  final Object? error;

  /// Interfaces that could carry a peer, i.e. usable, not loopback, and not a
  /// link type that cannot be shared (cellular, VPN).
  List<NetworkInterfaceSummary> get lanInterfaces =>
      interfaces.where((i) => i.isLanCandidate).toList(growable: false);

  /// Interfaces excluded from [lanInterfaces] because their link type cannot
  /// carry a peer (cellular, VPN). Kept so the diagnostics panel can explain why
  /// a device with an address is still reported as having no LAN.
  List<NetworkInterfaceSummary> get nonShareableInterfaces => interfaces
      .where((i) => i.isUsable && !i.isLoopback && !i.isLanCandidate)
      .toList(growable: false);

  /// Whether the shared-LAN transport is worth attempting.
  ///
  /// Derived from the actual interface list rather than from [reason] alone, so
  /// the two can never disagree. A probe that recorded `lanAvailable` while
  /// every interface turned out to be cellular would otherwise claim the LAN is
  /// fine - exactly the confusion this class exists to prevent. A failed
  /// enumeration is likewise *not* treated as "LAN available": we would rather
  /// offer a fallback unnecessarily than sit on a broken probe.
  bool get hasSharedLanCandidate =>
      reason == NetworkContextReason.lanAvailable && lanInterfaces.isNotEmpty;

  /// A one-line summary for the UI.
  String get summary => switch (reason) {
        NetworkContextReason.lanAvailable =>
          'LAN available on ${lanInterfaces.map((i) => i.name).join(', ')}',
        NetworkContextReason.noSharedSubnet => nonShareableInterfaces.isEmpty
            ? 'No shared network — only loopback is present'
            : 'No shared network — only '
                '${nonShareableInterfaces.map((i) => '${i.name} (${i.kind.name})').join(', ')} '
                'is present, which peers cannot reach',
        NetworkContextReason.noUsableInterface =>
          'A network interface exists but has no usable address yet',
        NetworkContextReason.enumerationFailed =>
          'Could not inspect network interfaces${error == null ? '' : ' ($error)'}',
      };
}

/// Probe the current network interfaces.
///
/// Never throws: a probe that can take the app down is worse than no probe, and
/// the caller needs an answer either way. Failure is reported through
/// [NetworkContext.reason] instead.
///
/// The address filter is intentionally the same shape as the discovery layer's
/// own dial-ability check, re-implemented locally so this file stays free of a
/// dependency on `mdns_discovery.dart` and can be unit tested in isolation.
Future<NetworkContext> probeNetworkContext() async {
  List<NetworkInterface> raw;
  try {
    raw = await NetworkInterface.list(
      includeLoopback: true,
      type: InternetAddressType.any,
    );
  } catch (error, stack) {
    coreLog.warning('could not enumerate network interfaces', error, stack);
    return NetworkContext(
      interfaces: const [],
      reason: NetworkContextReason.enumerationFailed,
      error: error,
    );
  }

  final summaries = <NetworkInterfaceSummary>[];
  for (final interface in raw) {
    // `NetworkInterface` exposes no `isLoopback`; the interface is the loopback
    // one exactly when every address it carries is. An interface with no
    // addresses at all is not loopback (it is a real NIC with no lease).
    final isLoopback =
        interface.addresses.isNotEmpty && interface.addresses.every((a) => a.isLoopback);
    final addresses = <String>[
      for (final address in interface.addresses)
        if (_isDialable(address)) address.address,
    ];
    summaries.add(
      NetworkInterfaceSummary(
        name: interface.name,
        addresses: addresses,
        isLoopback: isLoopback,
        kind: classifyInterface(interface.name),
      ),
    );
  }

  // Loopback is reported but never counts: a peer cannot dial 127.0.0.1 on
  // another device, and treating it as a shared link would make the app claim
  // the LAN is fine on a machine that is effectively offline. Cellular and VPN
  // interfaces are excluded for the same reason even though they carry a real
  // address - see [InterfaceKind].
  if (summaries.any((i) => i.isLanCandidate)) {
    return NetworkContext(
      interfaces: summaries,
      reason: NetworkContextReason.lanAvailable,
    );
  }

  final hasAnyInterface = summaries.any((i) => !i.isLoopback);
  return NetworkContext(
    interfaces: summaries,
    reason: hasAnyInterface
        ? NetworkContextReason.noUsableInterface
        : NetworkContextReason.noSharedSubnet,
  );
}

/// Whether [address] is something a peer on another device could dial.
///
/// Rejects the wildcard, loopback, and both link-local ranges. Link-local is the
/// interesting one: `169.254/16` and `fe80::/10` mean the interface failed to
/// get a real address, which is exactly the "no shared subnet" case even though
/// an address is technically present.
bool _isDialable(InternetAddress address) {
  if (address.address.isEmpty || address.rawAddress.isEmpty) return false;
  if (address.rawAddress.every((byte) => byte == 0)) return false;
  if (address.isLoopback || address.isLinkLocal) return false;
  if (address.type == InternetAddressType.IPv6) {
    if (address.rawAddress.first == 0xff) return false; // ff00::/8 multicast
  } else if (address.rawAddress.first >= 224 && address.rawAddress.first <= 239) {
    return false; // 224.0.0.0/4 multicast
  }
  return true;
}
