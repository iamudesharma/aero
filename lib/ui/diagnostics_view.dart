/// Diagnostics page.
///
/// Not a debugging afterthought — it is the primary tool for diagnosing the
/// two failure modes that are otherwise invisible:
///
///  1. On macOS 15+, an app without `NSLocalNetworkUsageDescription` has its LAN
///     access denied *silently*: no prompt, no error, no Settings entry. The
///     user just sees an empty peer list.
///  2. A port collision silently moves us to an ephemeral port, and if the
///     advertised port is stale nothing can connect.
///
/// Every field here exists because it answers "why is the peer list empty?"
library;

import 'package:flutter/material.dart';

import '../core/constants.dart';

class DiagnosticsPage extends StatefulWidget {
  const DiagnosticsPage({
    super.key,
    required this.snapshot,
    required this.entitlementLines,
    required this.onRefresh,
  });

  /// Live values gathered from the discovery and transport layers.
  final DiagnosticsSnapshot snapshot;

  /// Raw `codesign -d --entitlements -` output for the running app. Shows
  /// whether the sandbox actually granted what we asked for.
  final List<String> entitlementLines;

  final Future<void> Function() onRefresh;

  @override
  State<DiagnosticsPage> createState() => _DiagnosticsPageState();
}

class _DiagnosticsPageState extends State<DiagnosticsPage> {
  late Future<void> _refresh;

  @override
  void initState() {
    super.initState();
    _refresh = widget.onRefresh();
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.snapshot;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Diagnostics'),
        actions: [
          IconButton(
            onPressed: () => setState(() => _refresh = widget.onRefresh()),
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: FutureBuilder<void>(
        future: _refresh,
        builder: (context, _) => ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _HealthBanner(snapshot: s),
            const SizedBox(height: 16),
            _section(context, 'Discovery', [
              _row('Backend', s.discoveryBackend),
              _row('Browser ready', _yn(s.browserReady)),
              _row('Registered', _yn(s.registered)),
              _row('Peers seen', '${s.peersSeen}'),
              _row('Last error', s.discoveryError ?? 'none'),
            ]),
            const SizedBox(height: 12),
            _section(context, 'Transport', [
              _row('Transport', s.transportName),
              _row('Bound port', s.boundPort?.toString() ?? 'not bound'),
              _row('Preferred port', '$kPreferredPort'),
              _row('Cert fingerprint', s.certFingerprint ?? 'none'),
              _row('Serving', _yn(s.serving)),
            ]),
            const SizedBox(height: 12),
            _section(context, 'Transport tier', [
              _row('Selected', s.tier),
              _row('Reason', s.tierReason),
              _row('Live', s.liveReason),
              _row('Network', s.networkSummary),
              _row('Direct transfer', s.directState),
              _row('Hotspot', s.hotspot),
              _row('BLE advertising', s.bleAdvertising),
              _row('BLE rendezvous', s.bleRendezvous),
              _row('BLE found', s.bleFound),
              _row('Manual payload', s.manualPayload),
              if (s.manualError != 'none') _row('Manual error', s.manualError),
              if (s.tierDetail.isNotEmpty) _row('Detail', s.tierDetail),
            ]),
            const SizedBox(height: 12),
            _section(context, 'Identity', [
              _row('Device ID', s.deviceId.isEmpty ? 'none' : s.deviceId),
              _row('Device name', s.deviceName),
              _row('Public key', _shorten(s.publicKey)),
            ]),
            const SizedBox(height: 12),
            _section(
              context,
              'Platform requirements',
              s.platformNotes.map(_monospace).toList(growable: false),
            ),
            if (widget.entitlementLines.isNotEmpty) ...[
              const SizedBox(height: 12),
              _section(context, 'Signed entitlements', widget.entitlementLines
                  .map(_monospace)
                  .toList(growable: false)),
            ],
            const SizedBox(height: 24),
            _section(context, 'Copy report', [
              _monospace(s.toReport()),
            ]),
          ],
        ),
      ),
    );
  }

  Widget _section(BuildContext context, String title, List<Widget> children) =>
      Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: Theme.of(context).textTheme.titleSmall),
              const SizedBox(height: 8),
              ...children,
            ],
          ),
        ),
      );

  Widget _row(String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(width: 150, child: Text(label, style: const TextStyle(fontWeight: FontWeight.w500))),
            Expanded(child: Text(value)),
          ],
        ),
      );

  Widget _monospace(String s) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Text(s, style: const TextStyle(fontFamily: 'Menlo', fontSize: 11)),
      );

  static String _yn(bool? v) => v == null ? 'unknown' : (v ? 'yes' : 'NO');
  static String _shorten(String s) => s.length <= 16 ? s : '${s.substring(0, 8)}...${s.length} chars';
}

/// Values the diagnostics page renders. Plain data so it can be asserted on.
class DiagnosticsSnapshot {
  const DiagnosticsSnapshot({
    this.discoveryBackend = 'n/a',
    this.browserReady,
    this.registered,
    this.peersSeen = 0,
    this.discoveryError,
    this.transportName = 'n/a',
    this.boundPort,
    this.certFingerprint,
    this.serving,
    this.deviceId = '',
    this.deviceName = '',
    this.publicKey = '',
    this.platformNotes = const [],
    this.tier = 'not selected',
    this.tierReason = 'none',
    this.tierDetail = '',
    this.networkSummary = 'not probed',
    this.liveReason = 'none',
    this.directState = 'idle',
    this.hotspot = 'none',
    this.bleAdvertising = 'false',
    this.bleRendezvous = 'none',
    this.bleFound = 'none',
    this.manualPayload = 'none',
    this.manualError = 'none',
  });

  final String discoveryBackend;
  final bool? browserReady;
  final bool? registered;
  final int peersSeen;
  final String? discoveryError;
  final String transportName;
  final int? boundPort;
  final String? certFingerprint;
  final bool? serving;
  final String deviceId;
  final String deviceName;
  final String publicKey;
  final List<String> platformNotes;

  /// Which transport tier was selected and why. The first thing to read when a
  /// real-device run behaves unexpectedly.
  final String tier;
  final String tierReason;
  final String tierDetail;
  final String networkSummary;
  final String liveReason;

  /// Direct-transfer (offline fallback) state and the running hotspot.
  final String directState;
  final String hotspot;

  /// BLE rendezvous state (discovery only; never carries file data).
  final String bleAdvertising;
  final String bleRendezvous;
  final String bleFound;

  /// Manual pairing payload and any parse error.
  final String manualPayload;
  final String manualError;

  /// True only when everything needed for a working transfer is present.
  ///
  /// `peersSeen == 0` is deliberately NOT a failure: zero peers is a completely
  /// normal state when nobody else is running the app.
  bool get isHealthy =>
      browserReady == true &&
      registered == true &&
      serving == true &&
      boundPort != null &&
      deviceId.isNotEmpty &&
      discoveryError == null;

  String toReport() => [
        'healthy: $isHealthy',
        'discovery: $discoveryBackend (browserReady=$browserReady, registered=$registered, peers=$peersSeen)',
        if (discoveryError != null) 'discoveryError: $discoveryError',
        'transport: $transportName port=${boundPort ?? '-'} serving=$serving',
        'tier: $tier reason=$tierReason live=$liveReason',
        if (tierDetail.isNotEmpty) 'tierDetail: $tierDetail',
        'network: $networkSummary',
        'direct: $directState hotspot=$hotspot',
        'ble: advertising=$bleAdvertising rendezvous=$bleRendezvous found=$bleFound',
        'manual: $manualPayload${manualError == 'none' ? '' : ' error=$manualError'}',
        'fingerprint: ${certFingerprint ?? '-'}',
        'device: $deviceName ($deviceId)',
        ...platformNotes,
      ].join('\n');
}

/// Explains, in plain language, what this platform needs from the developer.
///
/// Surfacing these as text in the app — rather than only in docs — is
/// deliberate: a tester on a fresh machine is far more likely to read this than
/// to find the requirement in a README.
List<String> platformRequirementNotes(String platform) {
  switch (platform) {
    case 'macos':
      return const [
        'REQUIRED: NSLocalNetworkUsageDescription in Info.plist — without it macOS 15+ blocks '
            'the LAN *silently* (no prompt, no error, no Settings entry).',
        'REQUIRED: com.apple.security.network.client (outbound) AND '
            'com.apple.security.network.server (inbound) in BOTH DebugProfile and Release entitlements.',
        'REQUIRED: _aero._tcp listed in NSBonjourServices, or mDNS browsing is refused.',
        'For distribution: Developer ID + notarisation. Not needed for local LAN use.',
      ];
    case 'ios':
      return const [
        'REQUIRED: NSLocalNetworkUsageDescription + NSBonjourServices in Info.plist.',
        'User is prompted on first LAN access; deny and no peers appear.',
        'MultipeerConnectivity is deprecated (Xcode 27) — this app uses Network.framework instead.',
      ];
    case 'android':
      return const [
        'targetSdk 33+: NEARBY_WIFI_DEVICES runtime permission for P2P discovery.',
        'targetSdk 37+ (Android 17): ACCESS_LOCAL_NETWORK runtime permission is now REQUIRED; '
            'without it every local socket fails with SocketException.',
        'Android 17 alternative: use the system DiscoveryRequest picker, which needs no permission.',
        'CHANGE_WIFI_MULTICAST_STATE is needed to receive mDNS on older releases.',
        'Vendor ROMs (MIUI/HyperOS, ColorOS, vivo) may ship their own per-app LAN switch that '
            'ignores Android permissions entirely.',
      ];
    case 'windows':
      return const [
        'Firewall prompt on first inbound connection (Windows 11 24H2+).',
        'privateNetworkClientServer capability if packaged as MSIX.',
        'Packaging identity is NOT required for WinRT Wi-Fi Direct namespaces.',
      ];
    case 'linux':
      return const [
        'Requires a running Avahi daemon and an accessible D-Bus session bus.',
        'No sandbox: raw sockets and multicast work directly.',
        'Wi-Fi Direct / P2P group support is effectively unavailable — LAN mode only.',
      ];
    default:
      return const ['No platform-specific requirements recorded for this target.'];
  }
}

class _HealthBanner extends StatelessWidget {
  const _HealthBanner({required this.snapshot});

  final DiagnosticsSnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final healthy = snapshot.isHealthy;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: healthy ? scheme.primaryContainer : scheme.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(
            healthy ? Icons.check_circle_outline : Icons.error_outline,
            color: healthy ? scheme.onPrimaryContainer : scheme.onErrorContainer,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              healthy
                  ? 'All systems operational.'
                  : 'Setup problem detected — see the sections below. This is usually a missing '
                      'entitlement or permission rather than a code fault.',
              style: TextStyle(
                color: healthy ? scheme.onPrimaryContainer : scheme.onErrorContainer,
              ),
            ),
          ),
        ],
      ),
    );
  }
}