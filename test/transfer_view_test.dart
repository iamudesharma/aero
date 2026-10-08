import 'package:aero/core/contracts.dart';
import 'package:aero/core/models.dart';
import 'package:aero/ui/transfer_controller.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  FileEntry entry(String id, int size) => FileEntry(id: id, name: '$id.bin', size: size);

  group('formatting', () {
    test('bytes render at a sensible unit', () {
      expect(TransferView.formatBytes(0), '0 B');
      expect(TransferView.formatBytes(512), '512 B');
      expect(TransferView.formatBytes(1024), '1.0 KB');
      expect(TransferView.formatBytes(1536), '1.5 KB');
      expect(TransferView.formatBytes(1024 * 1024), '1.0 MB');
      expect(TransferView.formatBytes(3 * 1024 * 1024 * 1024), '3.0 GB');
    });

    test('large values drop the decimal rather than growing it', () {
      // Keeps the label from reflowing as the number grows.
      expect(TransferView.formatBytes(999 * 1024 * 1024), '999 MB');
    });

    test('durations switch unit sensibly', () {
      expect(TransferView.formatDuration(const Duration(seconds: 45)), '45s');
      expect(TransferView.formatDuration(const Duration(minutes: 2, seconds: 5)), '2m 05s');
      expect(TransferView.formatDuration(const Duration(hours: 1, minutes: 3)), '1h 03m');
    });
  });

  group('TransferView.fraction', () {
    TransferView make({required int sent, required int total, TransferOutcome? outcome}) =>
        TransferView(
          id: 't',
          peerName: 'p',
          direction: TransferDirection.sending,
          outcome: outcome ?? TransferOutcome.transferring,
          files: const {},
          bytesSent: sent,
          bytesTotal: total,
        );

    test('computes a fraction from bytes', () {
      expect(make(sent: 50, total: 100).fraction, 0.5);
    });

    test('is 1.0 when complete', () {
      expect(make(sent: 100, total: 100).fraction, 1.0);
    });

    test('never exceeds 1.0 on an over-report', () {
      expect(make(sent: 150, total: 100).fraction, 1.0);
    });

    test('is 0 for an active transfer of unknown size, not NaN', () {
      // A peer that reports size 0 (an empty file, or an unmeasurable stream)
      // must not produce a NaN progress bar.
      expect(make(sent: 10, total: 0).fraction, 0.0);
    });

    test('a finished zero-byte transfer reads as complete', () {
      expect(
        make(sent: 0, total: 0, outcome: TransferOutcome.succeeded).fraction,
        1.0,
      );
    });
  });

  group('FileProgress.fraction', () {
    test('a zero-byte file that finished is complete', () {
      const p = FileProgress(
        entry: FileEntry(id: 'a', name: 'empty', size: 0),
        state: TransferState.done,
      );
      expect(p.fraction, 1.0);
    });

    test('a zero-byte file still queued is not complete', () {
      const p = FileProgress(
        entry: FileEntry(id: 'a', name: 'empty', size: 0),
        state: TransferState.queued,
      );
      expect(p.fraction, 0.0);
    });

    test('progress tracks bytes against that file’s own size', () {
      const p = FileProgress(
        entry: FileEntry(id: 'a', name: 'x', size: 200),
        state: TransferState.transferring,
        bytesTransferred: 50,
      );
      expect(p.fraction, 0.25);
    });
  });

  group('TransferController', () {
    test('accumulates per-file bytes into a transfer total', () {
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.sending,
      );
      addTearDown(c.dispose);

      c.registerFiles([entry('a', 1000), entry('b', 1000)], state: TransferState.accepted);
      expect(c.view.bytesTotal, 2000);

      c
        ..onBytes(fileId: 'a', cumulativeBytes: 400)
        ..onBytes(fileId: 'b', cumulativeBytes: 100);

      expect(c.view.bytesSent, 500);
      expect(c.view.fraction, 0.25);
    });

    test('notifies listeners when bytes advance', () {
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.sending,
      )..registerFiles([entry('a', 100)], state: TransferState.accepted);
      addTearDown(c.dispose);

      var n = 0;
      c.addListener(() => n++);

      c
        ..onBytes(fileId: 'a', cumulativeBytes: 10)
        ..onBytes(fileId: 'a', cumulativeBytes: 20);

      expect(n, 2);
    });

    test('sets an outcome and freezes elapsed time', () {
      var now = DateTime(2026, 1, 1);
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.sending,
        clock: () => now,
      )..registerFiles([entry('a', 100)], state: TransferState.accepted);
      addTearDown(c.dispose);

      c
        ..onBytes(fileId: 'a', cumulativeBytes: 100)
        ..setOutcome(TransferOutcome.succeeded);

      expect(c.view.outcome, TransferOutcome.succeeded);
      expect(c.view.finishedAt, now);

      now = now.add(const Duration(minutes: 5));
      // Elapsed must stop accruing once the transfer is over, or a
      // finished card left on screen would show a growing duration.
      expect(c.view.elapsed, const Duration(seconds: 0));
    });

    test('marks an active transfer as cancellable, a finished one not', () {
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.sending,
      )..registerFiles([entry('a', 100)], state: TransferState.accepted);
      addTearDown(c.dispose);

      c.onBytes(fileId: 'a', cumulativeBytes: 1);
      expect(c.view.isCancellable, isTrue);

      c.setOutcome(TransferOutcome.succeeded);
      expect(c.view.isCancellable, isFalse);
    });

    test('records rejected files with their reasons', () {
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.receiving,
      )..registerFiles([entry('a', 10), entry('b', 10)], state: TransferState.accepted);
      addTearDown(c.dispose);

      c.addRejected('b', RejectReason.noSpace);

      expect(c.view.rejected.length, 1);
      expect(c.view.rejected.single.$1, 'b');
      expect(c.view.rejected.single.$2, RejectReason.noSpace);
    });

    test('preserves a failure message', () {
      final c = TransferController(
        id: 't1',
        peerName: 'Peer',
        direction: TransferDirection.sending,
      )..setOutcome(TransferOutcome.failed, errorMessage: 'Peer refused the transfer');
      addTearDown(c.dispose);

      expect(c.view.errorMessage, 'Peer refused the transfer');
    });
  });
}