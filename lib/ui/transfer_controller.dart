/// One in-flight or finished transfer, from either direction.
///
/// The UI renders this rather than raw protocol objects so that a send and a
/// receive with identical shapes drive the same widgets, and so a crash mid
/// transfer leaves a resumable record rather than an orphaned socket.
library;

import 'package:flutter/foundation.dart';

import '../core/contracts.dart';
import '../core/models.dart';

enum TransferDirection { sending, receiving }

enum TransferOutcome {
  pending,
  negotiating,
  pairing,
  transferring,
  verifying,
  succeeded,
  failed,
  cancelled,
}

/// Immutable snapshot for rendering.
class TransferView {
  const TransferView({
    required this.id,
    required this.peerName,
    required this.direction,
    required this.outcome,
    required this.files,
    required this.bytesSent,
    required this.bytesTotal,
    this.errorMessage,
    this.rejected = const [],
    this.startedAt,
    this.finishedAt,
  });

  final String id;
  final String peerName;
  final TransferDirection direction;
  final TransferOutcome outcome;

  /// Per-file state, keyed by file id.
  final Map<String, FileProgress> files;

  final int bytesSent;
  final int bytesTotal;

  /// Why this transfer failed, in words a user can act on.
  final String? errorMessage;

  /// Files the other side refused, with reasons.
  final List<(String, RejectReason)> rejected;

  final DateTime? startedAt;
  final DateTime? finishedAt;

  bool get isActive =>
      outcome == TransferOutcome.negotiating ||
      outcome == TransferOutcome.pairing ||
      outcome == TransferOutcome.transferring ||
      outcome == TransferOutcome.verifying ||
      outcome == TransferOutcome.pending;

  bool get isCancellable =>
      outcome == TransferOutcome.transferring ||
      outcome == TransferOutcome.negotiating ||
      outcome == TransferOutcome.pairing ||
      outcome == TransferOutcome.pending;

  /// 0.0 - 1.0 across the whole transfer. Zero when total size is unknown, so
  /// callers show an indeterminate bar instead of dividing by zero.
  double get fraction {
    if (bytesTotal <= 0) return isActive ? 0 : (outcome == TransferOutcome.succeeded ? 1 : 0);
    return (bytesSent / bytesTotal).clamp(0.0, 1.0);
  }

  Duration? get elapsed {
    final start = startedAt;
    if (start == null) return null;
    return (finishedAt ?? DateTime.now()).difference(start);
  }

  /// Instantaneous throughput in bytes/sec, averaged over the whole transfer.
  ///
  /// Averaged rather than sampled: it stays stable and meaningful, whereas a
  /// short window is dominated by chunk-boundary jitter and reads as noise.
  double get bytesPerSecond {
    final d = elapsed;
    if (d == null || d.inMilliseconds <= 0 || bytesSent <= 0) return 0;
    return bytesSent / (d.inMilliseconds / 1000.0);
  }

  static String formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    var value = bytes / 1024.0;
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return '${value.toStringAsFixed(value >= 100 ? 0 : 1)} ${units[unit]}';
  }

  static String formatDuration(Duration d) {
    if (d.inSeconds < 60) return '${d.inSeconds}s';
    final m = d.inMinutes;
    final s = d.inSeconds % 60;
    if (m < 60) return '${m}m ${s.toString().padLeft(2, '0')}s';
    return '${d.inHours}h ${(m % 60).toString().padLeft(2, '0')}m';
  }
}

/// Mutable state owned by the transfer layer; the UI listens and renders
/// [TransferView] snapshots.
class TransferController extends ChangeNotifier {
  TransferController({
    required this.id,
    required this.peerName,
    required this.direction,
    this.totalBytes = 0,
    DateTime Function()? clock,
  })  : _now = clock ?? DateTime.now,
        _view = TransferView(
          id: id,
          peerName: peerName,
          direction: direction,
          outcome: TransferOutcome.pending,
          files: const {},
          bytesSent: 0,
          bytesTotal: totalBytes,
        );

  final String id;
  final String peerName;
  final TransferDirection direction;
  final DateTime Function() _now;

  TransferView _view;
  TransferView get view => _view;

  int totalBytes;

  final Map<String, FileProgress> _files = {};
  final List<(String, RejectReason)> _rejected = [];

  /// True after [dispose], so a stray late callback can never throw
  /// `ChangeNotifier`'s "used after being disposed" error into a running
  /// transfer. The callback chain from `AeroPeerApi` into this object is
  /// asynchronous and can outlive the last screen the user had open, so this
  /// must be checked, not assumed.
  bool _disposed = false;

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  /// Emits the send side's byte progress. Coalescing happens here rather than
  /// in the UI so that every listener sees the same throttled cadence.
  void onBytes({required String fileId, required int cumulativeBytes, int? fileTotal}) {
    if (_disposed) return;
    final entry = _files[fileId]?.entry;
    _files[fileId] = FileProgress(
      entry: entry ??
          FileEntry(id: fileId, name: fileId, size: fileTotal ?? totalBytes),
      state: TransferState.transferring,
      bytesTransferred: cumulativeBytes,
    );
    _recompute();
  }

  void registerFiles(List<FileEntry> entries, {required TransferState state}) {
    if (_disposed) return;
    for (final e in entries) {
      _files[e.id] = FileProgress(entry: e, state: state);
    }
    totalBytes = entries.fold<int>(0, (sum, e) => sum + e.size);
    _recompute();
  }

  void markState(TransferState state, {String? fileId, String? error}) {
    if (_disposed) return;
    if (fileId != null) {
      final existing = _files[fileId];
      if (existing != null) {
        _files[fileId] = FileProgress(
          entry: existing.entry,
          state: state,
          bytesTransferred: existing.bytesTransferred,
          error: error,
        );
      }
    } else {
      for (final id in _files.keys) {
        final f = _files[id]!;
        _files[id] = FileProgress(
          entry: f.entry,
          state: state,
          bytesTransferred: f.bytesTransferred,
          error: error,
        );
      }
    }
    _recompute();
  }

  void setOutcome(TransferOutcome outcome, {String? errorMessage}) {
    if (_disposed) return;
    _view = _view.copyWithOutcome(
      outcome,
      Map.unmodifiable(Map.of(_files)),
      rejected: List.unmodifiable(_rejected),
      errorMessage: errorMessage,
      finishedAt: outcome == TransferOutcome.succeeded ||
              outcome == TransferOutcome.failed ||
              outcome == TransferOutcome.cancelled
          ? _now()
          : null,
    );
    notifyListeners();
  }

  /// Record a file the other side refused.
  ///
  /// Routed through [_recompute] rather than mutating the list alone, otherwise
  /// the snapshot the UI reads would never learn about the rejection — which
  /// is precisely the case a user most needs to see.
  void addRejected(String fileId, RejectReason reason) {
    if (_disposed) return;
    _rejected.add((fileId, reason));
    _recompute();
  }

  void _recompute() {
    if (_disposed) return;
    var sent = 0;
    for (final f in _files.values) {
      sent += f.bytesTransferred;
    }
    final nextOutcome = _view.outcome == TransferOutcome.pending ||
            _view.outcome == TransferOutcome.negotiating
        ? TransferOutcome.transferring
        : _view.outcome;

    _view = _view.copyWith(
      outcome: nextOutcome,
      files: Map.unmodifiable(Map.of(_files)),
      bytesSent: sent,
      bytesTotal: totalBytes > 0 ? totalBytes : _view.bytesTotal,
      rejected: List.unmodifiable(_rejected),
      startedAt: _view.startedAt ?? _now(),
    );
    notifyListeners();
  }
}

extension on TransferView {
  TransferView copyWith({
    TransferOutcome? outcome,
    Map<String, FileProgress>? files,
    int? bytesSent,
    int? bytesTotal,
    String? errorMessage,
    List<(String, RejectReason)>? rejected,
    DateTime? startedAt,
    DateTime? finishedAt,
  }) =>
      TransferView(
        id: id,
        peerName: peerName,
        direction: direction,
        outcome: outcome ?? this.outcome,
        files: files ?? this.files,
        bytesSent: bytesSent ?? this.bytesSent,
        bytesTotal: bytesTotal ?? this.bytesTotal,
        errorMessage: errorMessage ?? this.errorMessage,
        rejected: rejected ?? this.rejected,
        startedAt: startedAt ?? this.startedAt,
        finishedAt: finishedAt ?? this.finishedAt,
      );

  TransferView copyWithOutcome(
    TransferOutcome next,
    Map<String, FileProgress> f, {
    List<(String, RejectReason)>? rejected,
    String? errorMessage,
    DateTime? finishedAt,
  }) =>
      TransferView(
        id: id,
        peerName: peerName,
        direction: direction,
        outcome: next,
        files: f,
        bytesSent: bytesSent,
        bytesTotal: bytesTotal,
        errorMessage: errorMessage ?? this.errorMessage,
        rejected: rejected ?? this.rejected,
        startedAt: startedAt,
        finishedAt: finishedAt ?? this.finishedAt,
      );
}