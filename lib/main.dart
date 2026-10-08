/// Application entry point.
///
/// Kept thin on purpose: everything testable lives in [AppCoordinator] and the
/// UI layer, so this file only assembles them.
library;

import 'dart:async';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:logging/logging.dart';

import 'app/app_coordinator.dart';
import 'core/logging.dart';
import 'core/models.dart';
import 'core/network/manual_pairing.dart';
import 'ui/diagnostics_view.dart';
import 'ui/home_page.dart';
import 'ui/pairing_dialog.dart';

void main() {
  // Protocol-level chatter is opt-in: it is noisy and can name files, so it is
  // only enabled when explicitly requested.
  final verbose = Platform.environment['AERO_VERBOSE'] == '1';
  initLogging(level: verbose ? Level.ALL : Level.INFO);
  runApp(const AeroApp());
}

class AeroApp extends StatelessWidget {
  const AeroApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Aero',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF3B6EF6)),
        useMaterial3: true,
      ),
      home: const AeroShell(),
    );
  }
}

class AeroShell extends StatefulWidget {
  const AeroShell({super.key});

  @override
  State<AeroShell> createState() => _AeroShellState();
}

class _AeroShellState extends State<AeroShell> {
  final _coordinator = AppCoordinator();
  bool _pairingDialogOpen = false;
  bool _offerDialogOpen = false;

  @override
  void initState() {
    super.initState();
    _coordinator.addListener(_onChanged);
    unawaited(_coordinator.start());
  }

  @override
  void dispose() {
    _coordinator.removeListener(_onChanged);
    _coordinator.dispose();
    super.dispose();
  }

  void _onChanged() {
    if (!mounted) return;
    setState(() {});
    // Dialogs are driven from the model rather than from the button handler, so
    // an inbound offer or pairing request appears even if the user is not
    // looking at the peer list.
    _maybeShowPairing();
    _maybeShowOffer();
  }

  Future<void> _maybeShowPairing() async {
    if (_pairingDialogOpen || _coordinator.pendingPairings.isEmpty) return;
    final pending = _coordinator.pendingPairings.first;
    _pairingDialogOpen = true;
    try {
      await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (dialogContext) => PairingDialog(
          peerName: pending.peerName,
          proof: pending.proof,
          errorText: pending.error,
          // On the receiving side the wording must make clear that the *other*
          // device is asking to connect, so the user knows to look at that
          // screen rather than their own.
          isIncoming: !pending.isInitiator,
          onConfirm: () async {
            Navigator.of(dialogContext).pop();
            await _coordinator.confirmPairing(pending);
          },
          onCancel: () async {
            Navigator.of(dialogContext).pop();
            await _coordinator.rejectPairing(pending);
          },
        ),
      );
    } finally {
      _pairingDialogOpen = false;
    }
  }

  Future<void> _maybeShowOffer() async {
    if (_offerDialogOpen || _coordinator.pendingOffers.isEmpty) return;
    final pending = _coordinator.pendingOffers.first;
    _offerDialogOpen = true;
    try {
      await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (dialogContext) => IncomingOfferDialog(
          peerName: pending.peerName,
          offer: pending.offer,
          onRespond: (accept) async {
            // No pop here: `_respond` owns dismissal. Popping in both places
            // dismissed the dialog *and* the HomePage route behind it, which is
            // what produced the blank screen after accepting a transfer.
            _coordinator.respondToOffer(pending, accept);
            return true;
          },
        ),
      );
    } finally {
      _offerDialogOpen = false;
    }
  }

  Future<void> _sendTo(DiscoveredPeer peer) async {
    // file_picker 13 is a static API. `pickFiles` is multi-select by default
    // and returns an empty list on cancel — there is no longer a nullable
    // `platform` accessor and no `allowMultiple` flag.
    final picked = await FilePicker.pickFiles();
    final paths = picked.map((f) => f.path).whereType<String>().toList(growable: false);
    if (paths.isEmpty) return;

    final outcome = await _coordinator.sendTo(peer, paths);
    if (!mounted) return;

    final message = outcome.isSuccess
        ? 'Sent ${outcome.completed} file(s)'
            '${outcome.rejected > 0 ? ', ${outcome.rejected} declined' : ''}.'
        : outcome.isCancelled
            ? 'Transfer cancelled.'
            : outcome.message ?? 'Transfer failed.';

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  /// Pick files, then dial the peer from a pasted connection string.
  ///
  /// Goes through the same `sendTo` path as a discovered peer, so pairing and
  /// the transfer behave identically. Returns a message for the snackbar, or
  /// null when the user cancelled the file picker.
  Future<String?> _connectManually(String raw) async {
    final coordinator = _coordinator;
    final result = parseManualConnection(raw);
    if (!result.isSuccess) return result.message;

    final picked = await FilePicker.pickFiles();
    final paths = picked.map((f) => f.path).whereType<String>().toList(growable: false);
    if (paths.isEmpty) return null;

    final outcome = await coordinator.connectManually(raw, paths);
    if (!mounted) return null;
    if (outcome == null) {
      return coordinator.manualError ?? 'That connection string could not be used.';
    }
    if (outcome.isSuccess) {
      return 'Sent ${outcome.completed} file(s)'
          '${outcome.rejected > 0 ? ', ${outcome.rejected} declined' : ''}.';
    }
    if (outcome.isCancelled) return 'Transfer cancelled.';
    return outcome.message ?? 'Transfer failed.';
  }

  Future<void> _openDiagnostics() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => DiagnosticsPage(
          snapshot: _snapshot(),
          entitlementLines: const [],
          onRefresh: _coordinator.refresh,
        ),
      ),
    );
  }

  DiagnosticsSnapshot _snapshot() {
    final d = _coordinator.discoveryDiagnostics;
    final t = _coordinator.tierDiagnostics;
    final self = _coordinator.selfInfo;
    return DiagnosticsSnapshot(
      discoveryBackend: d['backend'] ?? 'mdns (bonsoir)',
      browserReady: _bool(d['browserReady']),
      registered: _bool(d['registered']),
      peersSeen: _coordinator.registry.count,
      discoveryError: d['error'],
      transportName: 'tcp-tls',
      boundPort: _coordinator.boundPort,
      certFingerprint: null,
      serving: _coordinator.boundPort != null,
      deviceId: self?.deviceId ?? '',
      deviceName: self?.deviceName ?? '',
      publicKey: self?.publicKey ?? '',
      platformNotes: platformRequirementNotes(Platform.operatingSystem),
      tier: t['tier'] ?? 'not selected',
      tierReason: t['tierReason'] ?? 'none',
      tierDetail: t['tierDetail'] ?? '',
      networkSummary: t['networkSummary'] ?? 'not probed',
      liveReason: t['liveReason'] ?? 'none',
      directState: t['directState'] ?? 'idle',
      hotspot: t['hotspot'] ?? 'none',
      bleAdvertising: t['bleAdvertising'] ?? 'false',
      bleRendezvous: t['bleRendezvous'] ?? 'none',
      bleFound: t['bleFound'] ?? 'none',
      manualPayload: t['manualPayload'] ?? 'none',
      manualError: t['manualError'] ?? 'none',
    );
  }

  static bool? _bool(String? v) => switch (v) {
        'true' || 'yes' => true,
        'false' || 'no' => false,
        _ => null,
      };

  @override
  Widget build(BuildContext context) {
    final coordinator = _coordinator;

    if (coordinator.phase == AppPhase.starting) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return HomePage(
      peers: coordinator.registry.peers,
      transfers: coordinator.transfers,
      discoveryProblem: coordinator.discoveryProblem,
      onRefresh: coordinator.refresh,
      onOpenDiagnostics: _openDiagnostics,
      onSendToPeer: _sendTo,
      onCancelTransfer: coordinator.cancelTransfer,
      onRevealFile: (_) async {},
      onPickFiles: null,
      receiveLocation: coordinator.receiveLocationHint,
      directTransferAvailable: coordinator.directTransferAvailable,
      directTransferHint: coordinator.directTransferHint,
      hotspotSsid: coordinator.hotspot?.ssid,
      hotspotPsk: coordinator.hotspot?.psk,
      canHostHotspot: coordinator.canHostHotspot,
      onBeginDirectTransfer: coordinator.beginDirectTransfer,
      onEndDirectTransfer: coordinator.endDirectTransfer,
      bleRendezvousAvailable: coordinator.bleRendezvousAvailable,
      isBleRendezvous: coordinator.isBleRendezvous,
      onBeginBleRendezvous: coordinator.beginBleRendezvous,
      manualConnectionString: coordinator.manualConnectionString,
      manualError: coordinator.manualError,
      manualReady: coordinator.directTransferState == DirectTransferState.manualReady,
      onBeginManualConnection: coordinator.beginManualConnection,
      onConnectManually: _connectManually,
    );
  }
}