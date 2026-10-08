/// QR rendering for the manual-pairing tier.
///
/// # Why a QR code at all
///
/// Manual pairing is the tier that works when every radio-based fallback is
/// blocked. Its weak point is transcription: a connection string is ~60
/// characters of hex and punctuation, and a single mistyped digit produces a
/// *valid-looking* payload that dials the wrong address. A QR code removes the
/// transcription step entirely - point one camera at the other screen.
///
/// # Why generation only
///
/// Generating is pure Dart (`package:qr`) and works on every target. *Scanning*
/// needs camera access and native code on both platforms, which is a much larger
/// commitment, so it is deliberately not built: the user types or pastes the
/// string if they cannot scan. The payload format is shared (`manual_pairing.dart`
/// owns it), so a scanner can be added later without touching this file or the
/// parser.
library;

import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:qr/qr.dart';

/// Build the QR module matrix for [data].
///
/// Returns a square matrix of booleans where `true` means "dark module". Pulled
/// out of the widget so it can be unit tested without a rendering pipeline -
/// "does this string produce a valid matrix" is a property worth asserting.
///
/// Uses [QrErrorCorrectLevel.medium] (~15% recovery): the payload is short, so
/// the code is small anyway, and medium tolerates a fingerprint or a reflection
/// on the screen without inflating the module count.
QrMatrix buildQrMatrix(String data) {
  final qrCode = QrCode(
    payload: QrPayload.fromString(data),
    errorCorrectLevel: QrErrorCorrectLevel.medium,
  );
  final image = QrImage(qrCode);
  final count = image.moduleCount;
  final modules = List<List<bool>>.generate(
    count,
    (row) => List<bool>.generate(count, (col) => image.isDark(row, col)),
    growable: false,
  );
  return QrMatrix(modules: modules, moduleCount: count, version: qrCode.typeNumber);
}

/// A rendered QR module matrix.
class QrMatrix {
  const QrMatrix({
    required this.modules,
    required this.moduleCount,
    required this.version,
  });

  /// Row-major modules; `true` is dark.
  final List<List<bool>> modules;

  /// Modules per side (QR version `n` has `4n + 17`).
  final int moduleCount;

  /// QR version, 1-40. Useful for diagnostics and for asserting the payload fits.
  final int version;

  /// Whether there is anything to draw.
  bool get isEmpty => moduleCount == 0;

  @override
  String toString() => 'QrMatrix(v$version, ${moduleCount}x$moduleCount)';
}

/// A widget that renders [data] as a QR code.
///
/// Painted manually rather than via a package widget so the rendering has no
/// extra dependency and the quiet zone is explicit - a QR code without its
/// mandatory 4-module quiet zone is unreliable to scan, which is exactly the
/// kind of bug that looks fine on screen and fails in practice.
class AeroQrCode extends StatelessWidget {
  const AeroQrCode({
    super.key,
    required this.data,
    this.size = 200,
    this.foreground = Colors.black,
    this.background = Colors.white,
  });

  final String data;
  final double size;
  final Color foreground;
  final Color background;

  @override
  Widget build(BuildContext context) {
    // Built once per data value rather than per frame: `QrImage` runs the mask
    // selection loop, which is not free.
    final matrix = buildQrMatrix(data);
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _QrPainter(
          matrix: matrix,
          foreground: foreground,
          background: background,
          label: data,
        ),
      ),
    );
  }
}

class _QrPainter extends CustomPainter {
  _QrPainter({
    required this.matrix,
    required this.foreground,
    required this.background,
    required this.label,
  });

  final QrMatrix matrix;
  final Color foreground;
  final Color background;

  /// The encoded text, used only for accessibility.
  final String label;

  /// Quiet zone, in modules, required by the QR spec (ISO/IEC 18004).
  static const int _quietZone = 4;

  @override
  void paint(Canvas canvas, Size size) {
    if (matrix.isEmpty) return;

    // White background first: a QR code on a transparent background scans badly
    // on a dark theme, and the quiet zone is only a quiet zone if it is light.
    final bg = Paint()..color = background;
    canvas.drawRect(Offset.zero & size, bg);

    final totalModules = matrix.moduleCount + _quietZone * 2;
    final module = size.shortestSide / totalModules;
    final fg = Paint()..color = foreground;

    for (var row = 0; row < matrix.moduleCount; row++) {
      for (var col = 0; col < matrix.moduleCount; col++) {
        if (!matrix.modules[row][col]) continue;
        // Adjacent dark modules are drawn as separate rects; at typical sizes
        // the hairline seams are invisible, and merging runs would add
        // complexity for no visible gain. If seams ever show, this is the place
        // to merge horizontal runs.
        final left = (col + _quietZone) * module;
        final top = (row + _quietZone) * module;
        canvas.drawRect(Rect.fromLTWH(left, top, module, module), fg);
      }
    }
  }

  @override
  bool shouldRepaint(_QrPainter oldDelegate) =>
      oldDelegate.matrix != matrix ||
      oldDelegate.foreground != foreground ||
      oldDelegate.background != background;

  @override
  SemanticsBuilderCallback get semanticsBuilder =>
      (Size size) => <CustomPainterSemantics>[
            CustomPainterSemantics(
              rect: Offset.zero & size,
              properties: SemanticsProperties(label: 'QR code: $label'),
            ),
          ];
}
