/// The 6-digit code comparison screen.
///
/// This is the security-critical moment of the whole app: it is the only moment
/// a user verifies they are not talking to an impostor. The UI is therefore
/// deliberately unambiguous — six large digits, an explicit countdown, and an
/// explicit "codes don't match" path rather than a silent failure.
library;

import 'dart:async';


import 'package:flutter/material.dart';

import '../core/models.dart';

class PairingDialog extends StatefulWidget {
  const PairingDialog({
    super.key,
    required this.peerName,
    required this.proof,
    required this.onConfirm,
    required this.onCancel,
    this.isIncoming = false,
    this.errorText,
  });

  final String peerName;

  /// True when the *other* device initiated: the user is being asked to check
  /// that peer's screen against this one.
  final bool isIncoming;

  /// The code this device computed. Both devices show the same value when they
  /// are genuinely talking to each other.
  final PairingProof proof;

  final Future<void> Function() onConfirm;
  final Future<void> Function() onCancel;

  /// Non-null when the other side rejected our code or an attempt is rate
  /// limited.
  final String? errorText;

  @override
  State<PairingDialog> createState() => _PairingDialogState();
}

class _PairingDialogState extends State<PairingDialog> {
  late Timer _ticker;
  late DateTime _now;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _now = DateTime.now();
    // Tick once a second purely to drive the countdown. Repainting six digits
    // every second is free; missing an expiry would leave a dead code on
    // screen looking valid.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() => _now = DateTime.now());
    });
  }

  @override
  void dispose() {
    _ticker.cancel();
    super.dispose();
  }

  Duration get _remaining => widget.proof.expiresAt.difference(_now);
  bool get _expired => _remaining.isNegative;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return AlertDialog(
      title: Row(
        children: [
          Icon(Icons.link, color: scheme.primary),
          const SizedBox(width: 12),
          Expanded(child: Text('Pair with ${widget.peerName}')),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.isIncoming
                  ? '${widget.peerName} wants to connect to this device. '
                      'Check that the same number appears on its screen, then confirm.'
                  : 'Check that the same number appears on the other device '
                      '(${widget.peerName}), then confirm.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 20),
            Center(child: _CodeDisplay(value: widget.proof.value, expired: _expired)),
            const SizedBox(height: 16),
            _ExpiryLine(remaining: _remaining, expired: _expired),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: scheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.info_outline, size: 18, color: scheme.onSurfaceVariant),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Anyone on this network can pretend to be another device. '
                      'Only continue if the numbers match exactly.',
                      style: theme.textTheme.bodySmall,
                    ),
                  ),
                ],
              ),
            ),
            if (widget.errorText != null) ...[
              const SizedBox(height: 16),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.error_outline, size: 18, color: scheme.error),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      widget.errorText!,
                      style: theme.textTheme.bodyMedium?.copyWith(color: scheme.error),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => widget.onCancel(),
          child: const Text('Cancel'),
        ),
        FilledButton.icon(
          onPressed: (_busy || _expired) ? null : () async {
            setState(() => _busy = true);
            try {
              await widget.onConfirm();
            } finally {
              if (mounted) setState(() => _busy = false);
            }
          },
          icon: _busy
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.check),
          label: const Text('Codes match'),
        ),
      ],
    );
  }
}

class _CodeDisplay extends StatelessWidget {
  const _CodeDisplay({required this.value, required this.expired});

  final String value;
  final bool expired;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = expired ? scheme.outline : scheme.primary;

    return Semantics(
      label: 'Pairing code ${value.split('').join(' ')}',
      child: ExcludeSemantics(
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            for (var i = 0; i < value.length; i++) ...[
              if (i > 0) const SizedBox(width: 6),
              Container(
                width: 46,
                height: 62,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: scheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: color, width: 2),
                ),
                child: Text(
                  value[i],
                  style: TextStyle(
                    fontSize: 34,
                    fontWeight: FontWeight.w700,
                    height: 1,
                    color: color,
                    fontFeatures: const [FontFeature.tabularFigures()],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ExpiryLine extends StatelessWidget {
  const _ExpiryLine({required this.remaining, required this.expired});

  final Duration remaining;
  final bool expired;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final style = Theme.of(context).textTheme.bodyMedium;

    if (expired) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.timer_off_outlined, size: 16, color: scheme.error),
          const SizedBox(width: 6),
          Text('Code expired — reconnect to get a new one', style: style?.copyWith(color: scheme.error)),
        ],
      );
    }

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.timer_outlined, size: 16, color: scheme.onSurfaceVariant),
        const SizedBox(width: 6),
        Text('Expires in ${remaining.inSeconds}s', style: style),
      ],
    );
  }
}

/// Incoming-offer confirmation.
///
/// Shown before any bytes move. Accepting is the user's consent to write to
/// disk, so rejected files are listed explicitly rather than silently dropped.
class IncomingOfferDialog extends StatefulWidget {
  const IncomingOfferDialog({
    super.key,
    required this.peerName,
    required this.offer,
    required this.onRespond,
  });

  final String peerName;
  final Offer offer;

  /// Return true to accept.
  final Future<bool> Function(bool accept) onRespond;

  @override
  State<IncomingOfferDialog> createState() => _IncomingOfferDialogState();
}

class _IncomingOfferDialogState extends State<IncomingOfferDialog> {
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final total = widget.offer.totalSize;
    return AlertDialog(
      title: Text('${widget.peerName} wants to send ${widget.offer.files.length} file(s)'),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Total ${_fmt(total)}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 12),
            Flexible(
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: widget.offer.files.length,
                itemBuilder: (context, i) {
                  final f = widget.offer.files[i];
                  return ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.insert_drive_file_outlined),
                    title: Text(f.relPath ?? f.name, overflow: TextOverflow.ellipsis),
                    trailing: Text(_fmt(f.size)),
                  );
                },
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => _respond(false),
          child: const Text('Reject'),
        ),
        FilledButton(
          onPressed: _busy ? null : () => _respond(true),
          child: const Text('Accept'),
        ),
      ],
    );
  }

  Future<void> _respond(bool accept) async {
    setState(() => _busy = true);
    try {
      final result = await widget.onRespond(accept);
      if (mounted && result) Navigator.of(context).pop();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  static String _fmt(int bytes) {
    if (bytes < 1024) return '$bytes B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    var v = bytes / 1024.0;
    var u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return '${v.toStringAsFixed(v >= 100 ? 0 : 1)} ${units[u]}';
  }
}