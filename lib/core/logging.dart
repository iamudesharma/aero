/// Logging setup. One place so verbose transport/protocol logging can be
/// toggled without touching call sites.
library;

import 'package:logging/logging.dart';

final Logger log = Logger('aero');

/// Protocol and framing chatter. Off by default: it is chatty and can reveal
/// file names in logs, so it must be opt-in.
final Logger protocolLog = Logger('aero.protocol');

/// Filesystem and crypto detail.
final Logger coreLog = Logger('aero.core');

void initLogging({Level level = Level.INFO}) {
  Logger.root.level = level;
  Logger.root.onRecord.listen((record) {
    // ignore: avoid_print
    print('${record.level.name.padRight(7)} ${record.loggerName}: ${record.message}');
    if (record.error != null) {
      // ignore: avoid_print
      print('        ${record.error}');
    }
  });
}