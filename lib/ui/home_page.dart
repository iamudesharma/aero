/// The main peer list and transfer screen.
///
/// Layout is a single scrolling column rather than multiple screens because the
/// AirDrop interaction is short-lived: a peer appears, you pick it, you confirm
/// a number, the transfer runs. Navigating away and back would add friction to
/// a flow that should take seconds.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/models.dart';
import 'qr_code.dart';
import 'transfer_controller.dart';

class HomePage extends StatelessWidget {
  const HomePage({
    super.key,
    required this.peers,
    required this.transfers,
    required this.discoveryProblem,
    required this.onRefresh,
    required this.onOpenDiagnostics,
    required this.onSendToPeer,
    required this.onCancelTransfer,
    required this.onRevealFile,
    this.onPickFiles,
    this.receiveLocation,
    this.directTransferAvailable = false,
    this.directTransferHint,
    this.hotspotSsid,
    this.hotspotPsk,
    this.onBeginDirectTransfer,
    this.onEndDirectTransfer,
    this.canHostHotspot = false,
    this.bleRendezvousAvailable = false,
    this.isBleRendezvous = false,
    this.onBeginBleRendezvous,
    this.manualConnectionString,
    this.manualError,
    this.manualReady = false,
    this.onBeginManualConnection,
    this.onConnectManually,
  });

  final List<DiscoveredPeer> peers;
  final List<TransferView> transfers;

  /// Non-null when discovery is broken, e.g. local-network permission denied.
  /// Shown in place of the peer list because "permission denied" and "nobody
  /// nearby" look identical otherwise.
  final String? discoveryProblem;

  final Future<void> Function() onRefresh;
  final VoidCallback onOpenDiagnostics;
  final Future<void> Function(DiscoveredPeer peer) onSendToPeer;
  final Future<void> Function(String transferId) onCancelTransfer;
  final Future<void> Function(String path) onRevealFile;

  /// Where received files are saved, e.g. `Downloads/Aero`. Null hides the
  /// hint. Without it a user has no way to know the app sandbox is not where
  /// the file went.
  final String? receiveLocation;
  final Future<void> Function()? onPickFiles;

  /// Whether to show the "Direct transfer" fallback action at all.
  final bool directTransferAvailable;

  /// A sentence describing the direct-transfer state, when one is in progress.
  final String? directTransferHint;

  /// Credentials of a running hotspot, shown so the other device can join.
  final String? hotspotSsid;
  final String? hotspotPsk;

  /// User-driven fallback controls. Never invoked automatically.
  final Future<void> Function()? onBeginDirectTransfer;
  final Future<void> Function()? onEndDirectTransfer;

  /// Whether this device created the hotspot (as opposed to joined one).
  final bool canHostHotspot;

  /// Whether to offer the BLE rendezvous action.
  final bool bleRendezvousAvailable;

  /// True when the current direct-transfer attempt is a BLE rendezvous.
  final bool isBleRendezvous;

  /// Start a BLE rendezvous (Android advertises, macOS scans).
  final Future<void> Function()? onBeginBleRendezvous;

  /// The `aero://` connection string this device should display, when ready.
  final String? manualConnectionString;

  /// A parse failure to surface.
  final String? manualError;

  /// True when a connection string is currently shown.
  final bool manualReady;

  /// Enter the manual tier and build the connection string.
  final VoidCallback? onBeginManualConnection;

  /// Parse a pasted string and dial it, returning the outcome for a snackbar.
  final Future<String?> Function(String raw)? onConnectManually;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Aero'),
        actions: [
          if (onPickFiles != null)
            IconButton(
              tooltip: 'Send files',
              onPressed: onPickFiles,
              icon: const Icon(Icons.upload_file),
            ),
          IconButton(
            tooltip: 'Refresh',
            onPressed: onRefresh,
            icon: const Icon(Icons.refresh),
          ),
          IconButton(
            tooltip: 'Diagnostics',
            onPressed: onOpenDiagnostics,
            icon: const Icon(Icons.troubleshoot),
          ),
        ],
      ),
      body: Column(
        children: [
          if (discoveryProblem != null) _ProblemBanner(message: discoveryProblem!),
          Expanded(
            child: RefreshIndicator(
              onRefresh: onRefresh,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  if (transfers.isNotEmpty) ...[
                    Text('Transfers', style: theme.textTheme.titleMedium),
                    const SizedBox(height: 8),
                    ...transfers.map((t) => Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: _TransferCard(
                            view: t,
                            onCancel: () => onCancelTransfer(t.id),
                          ),
                        )),
                    const SizedBox(height: 16),
                  ],
                  Text('Nearby devices', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 8),
                  if (directTransferAvailable || bleRendezvousAvailable) ...[
                    _DirectTransferCard(
                      hint: directTransferHint,
                      ssid: hotspotSsid,
                      psk: hotspotPsk,
                      isHosting: hotspotSsid != null,
                      canHost: canHostHotspot,
                      onBegin: onBeginDirectTransfer,
                      onEnd: onEndDirectTransfer,
                      bleAvailable: bleRendezvousAvailable,
                      isBle: isBleRendezvous,
                      onBeginBle: onBeginBleRendezvous,
                    ),
                    const SizedBox(height: 12),
                  ],
                  _ManualConnectionCard(
                    connectionString: manualConnectionString,
                    error: manualError,
                    isReady: manualReady,
                    onPrepare: onBeginManualConnection,
                    onConnect: onConnectManually,
                  ),
                  const SizedBox(height: 12),
                  if (receiveLocation != null && transfers.isEmpty)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Row(
                        children: [
                          Icon(Icons.folder_outlined, size: 16, color: theme.colorScheme.outline),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              'Received files are saved to $receiveLocation',
                              style: theme.textTheme.bodySmall,
                            ),
                          ),
                        ],
                      ),
                    ),
                  if (peers.isEmpty)
                    const _EmptyPeers()
                  else
                    ...peers.map((p) => Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: _PeerCard(
                            peer: p,
                            onSend: () => onSendToPeer(p),
                          ),
                        )),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ProblemBanner extends StatelessWidget {
  const _ProblemBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Material(
      color: scheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.wifi_off, color: scheme.onErrorContainer),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                message,
                style: TextStyle(color: scheme.onErrorContainer),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Shown when no shared network exists, so the user can stand up a direct link
/// without a router.
///
/// Deliberately not automatic: creating an access point is visible and consumes
/// power, so it happens only when the user asks. On the hosting side it shows
/// the SSID and passphrase to type on the other device; on the joining side it
/// explains that the *other* device must start one.
class _DirectTransferCard extends StatelessWidget {
  const _DirectTransferCard({
    required this.hint,
    required this.ssid,
    required this.psk,
    required this.isHosting,
    required this.canHost,
    required this.onBegin,
    required this.onEnd,
    required this.bleAvailable,
    required this.isBle,
    required this.onBeginBle,
  });

  final String? hint;
  final String? ssid;
  final String? psk;
  final bool isHosting;
  final bool canHost;
  final Future<void> Function()? onBegin;
  final Future<void> Function()? onEnd;
  final bool bleAvailable;
  final bool isBle;
  final Future<void> Function()? onBeginBle;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Card(
      color: scheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.wifi_tethering, size: 18, color: scheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text('Direct transfer', style: theme.textTheme.titleSmall),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              canHost
                  ? 'No shared Wi-Fi? Turn this device into a hotspot and the '
                      'other device can join it directly — no router needed.'
                  : 'No shared Wi-Fi? Start a hotspot on the other device, then '
                      'join it from this one. Aero will connect automatically.',
              style: theme.textTheme.bodySmall,
            ),
            if (hint != null) ...[
              const SizedBox(height: 8),
              Text(hint!, style: theme.textTheme.bodySmall),
            ],
            if (ssid != null) ...[
              const SizedBox(height: 10),
              _CredentialRow(label: 'Network', value: ssid!),
              if (psk != null && psk!.isNotEmpty)
                _CredentialRow(label: 'Password', value: psk!),
              const SizedBox(height: 4),
              Text(
                'On the other device, open Wi-Fi settings, join this network, '
                'then return here. Both devices will find each other.',
                style: theme.textTheme.bodySmall?.copyWith(color: scheme.outline),
              ),
            ],
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (!isHosting && !isBle)
                  FilledButton.tonalIcon(
                    onPressed: onBegin,
                    icon: const Icon(Icons.wifi_find, size: 18),
                    label: Text(canHost ? 'Start hotspot' : 'Join hotspot'),
                  )
                else if (isHosting)
                  FilledButton.tonalIcon(
                    onPressed: onEnd,
                    icon: const Icon(Icons.wifi_off, size: 18),
                    label: const Text('Stop hotspot'),
                  ),
                if (!isHosting && bleAvailable)
                  OutlinedButton.icon(
                    onPressed: isBle ? onEnd : onBeginBle,
                    icon: const Icon(Icons.bluetooth_searching, size: 18),
                    label: Text(isBle ? 'Stop Bluetooth' : 'Find over Bluetooth'),
                  ),
              ],
            ),
            if (bleAvailable && !isBle) ...[
              const SizedBox(height: 6),
              Text(
                'Bluetooth is used only to find the other device, never to send '
                'files.',
                style: theme.textTheme.bodySmall?.copyWith(color: scheme.outline),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Manual pairing: the fallback that needs neither mDNS nor Bluetooth.
///
/// Shows this device's connection string (to read to the other device) and an
/// input for the other device's string. Deliberately always visible: it is the
/// one tier that works when every radio-based one is blocked, so hiding it would
/// leave a user with no path at all.
class _ManualConnectionCard extends StatefulWidget {
  const _ManualConnectionCard({
    required this.connectionString,
    required this.error,
    required this.isReady,
    required this.onPrepare,
    required this.onConnect,
  });

  final String? connectionString;
  final String? error;
  final bool isReady;
  final VoidCallback? onPrepare;
  final Future<String?> Function(String raw)? onConnect;

  @override
  State<_ManualConnectionCard> createState() => _ManualConnectionCardState();
}

class _ManualConnectionCardState extends State<_ManualConnectionCard> {
  final _controller = TextEditingController();
  bool _showInput = false;
  bool _busy = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    final onConnect = widget.onConnect;
    if (onConnect == null) return;
    setState(() => _busy = true);
    final message = await onConnect(_controller.text);
    if (!mounted) return;
    setState(() => _busy = false);
    if (message != null) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final connectionString = widget.connectionString;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.qr_code_2, size: 18, color: scheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text('Connect manually', style: theme.textTheme.titleSmall),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              'Works even when Wi-Fi discovery and Bluetooth are blocked. Share '
              'this connection string with the other device, or enter theirs.',
              style: theme.textTheme.bodySmall,
            ),
            if (connectionString != null) ...[
              const SizedBox(height: 10),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // The QR removes transcription entirely: the other device
                  // points a camera at it. Purely additive - the string below
                  // still works if scanning is not available.
                  AeroQrCode(data: connectionString, size: 160),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Scan this on the other device, or copy the string.',
                          style: theme.textTheme.bodySmall,
                        ),
                        const SizedBox(height: 8),
                        SelectableText(
                          connectionString,
                          style: const TextStyle(fontFamily: 'Menlo', fontSize: 12),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  TextButton.icon(
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: connectionString));
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Copied connection string')),
                        );
                      }
                    },
                    icon: const Icon(Icons.copy, size: 16),
                    label: const Text('Copy'),
                  ),
                ],
              ),
            ],
            if (widget.error != null) ...[
              const SizedBox(height: 6),
              Text(
                widget.error!,
                style: theme.textTheme.bodySmall?.copyWith(color: scheme.error),
              ),
            ],
            const SizedBox(height: 8),
            if (!_showInput)
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  OutlinedButton.icon(
                    onPressed: widget.onPrepare,
                    icon: const Icon(Icons.ios_share, size: 18),
                    label: Text(widget.isReady ? 'Refresh my string' : 'Show my string'),
                  ),
                  TextButton.icon(
                    onPressed: () => setState(() => _showInput = true),
                    icon: const Icon(Icons.keyboard, size: 18),
                    label: const Text('Enter a string'),
                  ),
                ],
              )
            else ...[
              TextField(
                controller: _controller,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Paste the other device\'s connection string',
                  hintText: 'aero://connect?host=192.168.1.5&port=44353',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                onSubmitted: (_) => _connect(),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  FilledButton.icon(
                    onPressed: _busy ? null : _connect,
                    icon: _busy
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.link, size: 18),
                    label: const Text('Connect'),
                  ),
                  const SizedBox(width: 8),
                  TextButton(
                    onPressed: _busy ? null : () => setState(() => _showInput = false),
                    child: const Text('Cancel'),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                'You will still see a 6-digit code to confirm on both devices.',
                style: theme.textTheme.bodySmall?.copyWith(color: scheme.outline),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// One selectable credential line, with a copy button.
class _CredentialRow extends StatelessWidget {
  const _CredentialRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 80,
            child: Text(label, style: theme.textTheme.bodySmall),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(fontFamily: 'Menlo', fontSize: 13),
            ),
          ),
          IconButton(
            tooltip: 'Copy',
            visualDensity: VisualDensity.compact,
            icon: const Icon(Icons.copy, size: 16),
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: value));
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('Copied $label')),
                );
              }
            },
          ),
        ],
      ),
    );
  }
}

class _EmptyPeers extends StatelessWidget {
  const _EmptyPeers();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 48),
      child: Column(
        children: [
          Icon(Icons.devices_other, size: 48, color: theme.colorScheme.outline),
          const SizedBox(height: 16),
          Text('Looking for devices…', style: theme.textTheme.titleSmall),
          const SizedBox(height: 8),
          Text(
            'Run Aero on another device on the same network.\n'
            'Both devices need to be on the same Wi-Fi — no router or internet '
            'connection is required, but they must share one network.',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

class _PeerCard extends StatelessWidget {
  const _PeerCard({required this.peer, required this.onSend});

  final DiscoveredPeer peer;
  final Future<void> Function() onSend;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final info = peer.info;

    return Card(
      child: ListTile(
        leading: CircleAvatar(child: Text(_initial(info.deviceName))),
        title: Text(info.deviceName),
        subtitle: Row(
          children: [
            Text(_osLabel(info.os)),
            if (!info.isCompatible) ...[
              const SizedBox(width: 8),
              // Surfaced rather than hidden: a version mismatch explains a
              // transfer that otherwise just refuses to start.
              Icon(Icons.warning_amber, size: 14, color: theme.colorScheme.error),
              const SizedBox(width: 2),
              Text(
                'incompatible v${info.protocolVersion}',
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            if (info.trustState == TrustState.known) ...[
              const SizedBox(width: 8),
              Icon(Icons.verified_user_outlined, size: 14, color: theme.colorScheme.primary),
              const SizedBox(width: 2),
              Text('Known', style: theme.textTheme.bodySmall),
            ] else if (info.trustState == TrustState.identityConflict) ...[
              const SizedBox(width: 8),
              Icon(Icons.gpp_bad_outlined, size: 14, color: theme.colorScheme.error),
              const SizedBox(width: 2),
              Text(
                'Identity changed',
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
              ),
            ],
          ],
        ),
        trailing: FilledButton.tonalIcon(
          onPressed: info.canReceive ? onSend : null,
          icon: const Icon(Icons.send, size: 18),
          label: const Text('Send'),
        ),
        isThreeLine: false,
      ),
    );
  }

  static String _initial(String name) {
    final t = name.trim();
    return t.isEmpty ? '?' : t[0].toUpperCase();
  }

  static String _osLabel(AeroOs os) => switch (os) {
        AeroOs.macos => 'macOS',
        AeroOs.ios => 'iOS',
        AeroOs.android => 'Android',
        AeroOs.windows => 'Windows',
        AeroOs.linux => 'Linux',
        AeroOs.web => 'Web',
        AeroOs.unknown => 'Unknown device',
      };
}

class _TransferCard extends StatelessWidget {
  const _TransferCard({required this.view, required this.onCancel});

  final TransferView view;
  final Future<void> Function() onCancel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final sending = view.direction == TransferDirection.sending;
    final indeterminate = view.bytesTotal <= 0 && view.isActive;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(sending ? Icons.north_east : Icons.south_west, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '${sending ? 'To' : 'From'} ${view.peerName}',
                    style: theme.textTheme.titleSmall,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                _OutcomeChip(outcome: view.outcome),
                if (view.isCancellable)
                  IconButton(
                    onPressed: onCancel,
                    icon: const Icon(Icons.close, size: 18),
                    tooltip: 'Cancel',
                    visualDensity: VisualDensity.compact,
                  ),
              ],
            ),
            const SizedBox(height: 8),
            indeterminate
                ? const LinearProgressIndicator()
                : LinearProgressIndicator(value: view.fraction),
            const SizedBox(height: 8),
            Row(
              children: [
                Text(
                  '${TransferView.formatBytes(view.bytesSent)}'
                  '${view.bytesTotal > 0 ? ' / ${TransferView.formatBytes(view.bytesTotal)}' : ''}',
                  style: theme.textTheme.bodySmall,
                ),
                const Spacer(),
                if (view.bytesPerSecond > 0)
                  Text(
                    '${TransferView.formatBytes(view.bytesPerSecond.round())}/s',
                    style: theme.textTheme.bodySmall,
                  ),
                if (view.elapsed != null) ...[
                  const SizedBox(width: 12),
                  Text(
                    TransferView.formatDuration(view.elapsed!),
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ],
            ),
            if (view.errorMessage != null) ...[
              const SizedBox(height: 8),
              Text(
                view.errorMessage!,
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            // Surface rejected files explicitly. A silently missing file is the
            // most common way a transfer app loses a user's trust.
            if (view.rejected.isNotEmpty) ...[
              const SizedBox(height: 8),
              ...view.rejected.map(
                (r) => Text(
                  'Rejected ${r.$1}: ${_reasonText(r.$2)}',
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  static String _reasonText(RejectReason r) => switch (r) {
        RejectReason.noSpace => 'not enough disk space',
        RejectReason.tooLarge => 'file too large',
        RejectReason.tooManyFiles => 'too many files',
        RejectReason.unsupportedName => 'unsupported file name',
        RejectReason.duplicate => 'duplicate file',
        RejectReason.notAccepted => 'declined by receiver',
        RejectReason.unknown => 'refused',
      };
}

class _OutcomeChip extends StatelessWidget {
  const _OutcomeChip({required this.outcome});

  final TransferOutcome outcome;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (label, color) = switch (outcome) {
      TransferOutcome.succeeded => ('Done', scheme.primary),
      TransferOutcome.failed => ('Failed', scheme.error),
      TransferOutcome.cancelled => ('Cancelled', scheme.outline),
      TransferOutcome.pairing => ('Pairing', scheme.tertiary),
      TransferOutcome.verifying => ('Verifying', scheme.tertiary),
      TransferOutcome.negotiating => ('Negotiating', scheme.tertiary),
      _ => ('Transferring', scheme.primary),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(label, style: TextStyle(fontSize: 11, color: color)),
    );
  }
}