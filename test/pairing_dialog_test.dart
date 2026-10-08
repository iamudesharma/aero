/// Widget tests for the two dialogs, driven by the bugs they exist to prevent:
///
///  * the incoming-offer dialog used to be popped twice — once by the caller
///    and once by its own button handler — which dismissed the HomePage behind
///    it and left a blank screen after accepting a transfer;
///  * the receiving device used to show no pairing code at all.
library;

import 'package:aero/core/constants.dart';
import 'package:aero/core/models.dart';
import 'package:aero/ui/pairing_dialog.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Offer _offer() => const Offer(
      sessionId: 's1',
      totalSize: 2048,
      files: [
        FileEntry(id: 'a', name: 'photo.jpg', size: 1024),
        FileEntry(id: 'b', name: 'notes.txt', size: 1024),
      ],
    );

PairingProof _proof() => PairingProof(
      method: Crypto.pairingMethod,
      value: '472905',
      expiresAt: DateTime.now().add(Pairing.codeLifetime),
    );

void main() {
  group('IncomingOfferDialog', () {
    testWidgets('accepting dismisses only the dialog, leaving the app visible', (tester) async {
      var responded = false;

      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) => Scaffold(
            body: ElevatedButton(
              onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => IncomingOfferDialog(
                  peerName: 'Other Mac',
                  offer: _offer(),
                  onRespond: (accept) async {
                    responded = true;
                    return true;
                  },
                ),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ));

      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();
      expect(find.text('Accept'), findsOneWidget);

      await tester.tap(find.text('Accept'));
      await tester.pumpAndSettle();

      expect(responded, isTrue);
      // The dialog is gone...
      expect(find.text('Accept'), findsNothing);
      // ...but the page behind it is still there. A second pop would have
      // removed this and produced the blank screen.
      expect(find.text('open'), findsOneWidget);
    });

    testWidgets('rejecting also leaves the app visible', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) => Scaffold(
            body: ElevatedButton(
              onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => IncomingOfferDialog(
                  peerName: 'Other Mac',
                  offer: _offer(),
                  onRespond: (accept) async => true,
                ),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ));

      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Reject'));
      await tester.pumpAndSettle();

      expect(find.text('Reject'), findsNothing);
      expect(find.text('open'), findsOneWidget);
    });

    testWidgets('lists the files and total size before anything is written', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: IncomingOfferDialog(
          peerName: 'Other Mac',
          offer: _offer(),
          onRespond: (accept) async => true,
        ),
      ));
      await tester.pumpAndSettle();

      expect(find.textContaining('Other Mac'), findsOneWidget);
      expect(find.text('photo.jpg'), findsOneWidget);
      expect(find.text('notes.txt'), findsOneWidget);
      expect(find.text('Total 2.0 KB'), findsOneWidget);
    });
  });

  group('PairingDialog', () {
    testWidgets('shows the code and wording for an outgoing request', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: PairingDialog(
          peerName: 'Other Mac',
          proof: _proof(),
          onConfirm: () async {},
          onCancel: () async {},
        ),
      ));
      await tester.pumpAndSettle();

      expect(
        find.textContaining('appears on the other device'),
        findsOneWidget,
      );
      // Tabular digits are rendered individually.
      for (final d in '472905'.split('')) {
        expect(find.text(d), findsWidgets);
      }
      // The countdown ticks, so assert the label rather than an exact second.
      expect(find.textContaining('Expires in'), findsOneWidget);
    });

    testWidgets('shows wording that names the asking device for an inbound request', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: PairingDialog(
          peerName: 'Caller Mac',
          proof: _proof(),
          isIncoming: true,
          onConfirm: () async {},
          onCancel: () async {},
        ),
      ));
      await tester.pumpAndSettle();

      expect(find.textContaining('wants to connect to this device'), findsOneWidget);
      expect(find.textContaining('Caller Mac'), findsWidgets);
    });

    testWidgets('confirming reports exactly once and does not pop itself', (tester) async {
      // The dialog owns no navigation: the caller dismisses it. A dialog that
      // pops itself *and* is popped by its caller is the bug this guards.
      var confirms = 0;
      await tester.pumpWidget(MaterialApp(
        home: PairingDialog(
          peerName: 'Other Mac',
          proof: _proof(),
          onConfirm: () async => confirms++,
          onCancel: () async {},
        ),
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Codes match'));
      await tester.pumpAndSettle();

      expect(confirms, 1);
      // Still mounted: popping is the caller's job, so the dialog must remain.
      expect(find.text('Codes match'), findsOneWidget);
    });

    testWidgets('an expired code cannot be confirmed', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: PairingDialog(
          peerName: 'Other Mac',
          proof: PairingProof(
            method: Crypto.pairingMethod,
            value: '000000',
            expiresAt: DateTime.now().subtract(const Duration(seconds: 1)),
          ),
          onConfirm: () async {},
          onCancel: () async {},
        ),
      ));
      await tester.pumpAndSettle();

      expect(find.textContaining('expired'), findsOneWidget);
      final button = tester.widget<FilledButton>(find.byType(FilledButton));
      expect(button.onPressed, isNull, reason: 'an expired code must not be confirmable');
    });

    testWidgets('surfaces the rate-limit error text', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: PairingDialog(
          peerName: 'Other Mac',
          proof: _proof(),
          errorText: 'Too many attempts. Wait a minute.',
          onConfirm: () async {},
          onCancel: () async {},
        ),
      ));
      await tester.pumpAndSettle();

      expect(find.text('Too many attempts. Wait a minute.'), findsOneWidget);
    });
  });
}
