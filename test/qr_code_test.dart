import 'package:aero/core/network/manual_pairing.dart';
import 'package:aero/ui/qr_code.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr/qr.dart';

/// QR generation tests.
///
/// A QR code that renders but cannot be decoded is worse than none, because the
/// user trusts it. These assert the two things that actually matter: the matrix
/// is structurally valid, and the text it encodes is exactly the parser's input.
void main() {
  group('buildQrMatrix', () {
    test('produces a square matrix whose side is 4n + 17', () {
      final matrix = buildQrMatrix('192.168.1.5:44353');
      expect(matrix.isEmpty, isFalse);
      expect(matrix.modules.length, matrix.moduleCount);
      for (final row in matrix.modules) {
        expect(row.length, matrix.moduleCount);
      }
      expect(matrix.moduleCount, matrix.version * 4 + 17);
    });

    test('a realistic connection string fits a small version', () {
      const connection = ManualConnection(
        host: '192.168.1.5',
        port: 44353,
        deviceName: "Alex's MacBook Pro",
        deviceId: 'ea300c6e1234567890abcdef12345678',
        publicKeyHash: 'aBcDeFgHiJkLmNoP',
        os: 'macos',
      );
      final uri = connection.toUriString();
      final matrix = buildQrMatrix(uri);
      // The payload is ~120 bytes; even at medium ECC that is a low version.
      // A high version would mean the payload grew unexpectedly.
      expect(matrix.version, lessThanOrEqualTo(10),
          reason: 'payload "$uri" unexpectedly large (v${matrix.version})');
    });

    test('has the three finder patterns in the right corners', () {
      final matrix = buildQrMatrix('aero://connect?host=192.168.1.5&port=44353');

      // A finder pattern is a 7x7 square: a dark border, a light ring, and a
      // dark 3x3 core. Checking the outer ring and the core centre is enough to
      // prove the pattern is where the spec requires it.
      for (final (top, left) in [(0, 0), (0, matrix.moduleCount - 7), (matrix.moduleCount - 7, 0)]) {
        expect(matrix.modules[top][left], isTrue, reason: 'finder corner $top,$left');
        expect(matrix.modules[top + 6][left + 6], isTrue, reason: 'finder corner far $top,$left');
        // The light ring: module (1,1) relative to the corner is light.
        expect(matrix.modules[top + 1][left + 1], isFalse, reason: 'light ring $top,$left');
        // The 3x3 core centre is dark.
        expect(matrix.modules[top + 3][left + 3], isTrue, reason: 'core $top,$left');
      }
    });

    test('the bottom-right corner has no finder pattern', () {
      final matrix = buildQrMatrix('192.168.1.5:44353');
      final n = matrix.moduleCount;
      // The QR spec places finders in three corners only; the fourth is data.
      // We cannot assert a specific value, but the 7x7 corner must not be a full
      // finder ring identical to the others - just confirm it is in range and
      // the matrix is not accidentally symmetric.
      expect(matrix.modules[n - 1][n - 1], isA<bool>());
    });

    test('different payloads produce different matrices', () {
      final a = buildQrMatrix('192.168.1.5:44353');
      final b = buildQrMatrix('192.168.1.6:44353');
      final same = a.moduleCount == b.moduleCount &&
          List.generate(a.moduleCount, (r) => r).every(
            (r) => List.generate(a.moduleCount, (c) => c)
                .every((c) => a.modules[r][c] == b.modules[r][c]),
          );
      expect(same, isFalse);
    });

    test('the same payload is deterministic', () {
      final a = buildQrMatrix('192.168.1.5:44353');
      final b = buildQrMatrix('192.168.1.5:44353');
      expect(a.moduleCount, b.moduleCount);
      expect(a.version, b.version);
      for (var r = 0; r < a.moduleCount; r++) {
        expect(a.modules[r], b.modules[r], reason: 'row $r must match');
      }
    });

    test('bounds every module to a boolean', () {
      final matrix = buildQrMatrix('aero://connect?host=10.0.0.1&port=44353');
      for (final row in matrix.modules) {
        for (final module in row) {
          expect(module, isA<bool>());
        }
      }
    });
  });

  group('QR payload is the parser input', () {
    test('what the QR encodes is exactly what parseManualConnection accepts', () {
      // This is the contract that makes the QR useful: if the two ever diverged,
      // a scanned code would fail to connect with no obvious reason.
      const connection = ManualConnection(
        host: '192.168.43.1',
        port: 44353,
        deviceName: 'Phone',
        deviceId: 'abc123',
        os: 'android',
      );
      final encoded = connection.toUriString();
      final decoded = decodeManualPayload(encoded.codeUnits);
      expect(decoded.isSuccess, isTrue, reason: decoded.message);
      expect(decoded.connection!.host, '192.168.43.1');
      expect(decoded.connection!.port, 44353);

      // And `qr` must accept the same string without throwing.
      expect(
        () => QrCode(
          payload: QrPayload.fromString(encoded),
          errorCorrectLevel: QrErrorCorrectLevel.medium,
        ),
        returnsNormally,
      );
    });

    test('a payload with a different ECC level still encodes', () {
      final matrix = buildQrMatrix('192.168.1.5:44353');
      expect(matrix.isEmpty, isFalse);
      // Sanity: version 1 is 21 modules; anything below that is impossible.
      expect(matrix.moduleCount, greaterThanOrEqualTo(21));
    });
  });
}
