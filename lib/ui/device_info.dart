/// Platform and device metadata used to build our own `PeerInfo`.
///
/// Kept separate from `PeerInfo` itself because gathering it is inherently
/// platform-specific and can fail (e.g. reading a model string on an unusual
/// host), whereas `PeerInfo` is a pure value object.
library;

import 'dart:io';

import 'package:path_provider/path_provider.dart';

import '../core/models.dart';

/// Detect the OS we are running on.
AeroOs currentOs() {
  if (Platform.isMacOS) return AeroOs.macos;
  if (Platform.isIOS) return AeroOs.ios;
  if (Platform.isAndroid) return AeroOs.android;
  if (Platform.isWindows) return AeroOs.windows;
  if (Platform.isLinux) return AeroOs.linux;
  return AeroOs.unknown;
}

/// A human-facing device name.
///
/// `Platform.environment['HOSTNAME']` is populated on macOS and Linux but not
/// reliably on Windows, and even where present it can be a generic string like
/// "localhost" in a sandboxed app, so it is only accepted when it looks like a
/// real host name.
String platformDeviceName() {
  final env = Platform.environment;
  final host = (env['HOSTNAME'] ?? env['COMPUTERNAME'] ?? '').trim();
  if (_looksLikeRealHostName(host)) return host;

  // `scutil --get ComputerName` is the most reliable source on macOS.
  final macName = _runSync(['/usr/bin/scutil', '--get', 'ComputerName'])
      ?.replaceAll(RegExp(r'Computer Name :\s*'), '')
      .trim();
  if (macName != null && macName.isNotEmpty && macName != 'localhost') {
    return macName;
  }

  return Platform.isMacOS ? 'This Mac' : 'This device';
}

bool _looksLikeRealHostName(String s) {
  if (s.isEmpty || s.length > 64) return false;
  if (s == 'localhost' || s == 'localhost.local') return false;
  if (s.endsWith('.local')) return false;
  return RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]*$').hasMatch(s);
}

/// A best-effort hardware model string, purely for display ("MacBook Pro").
String platformDeviceModel() {
  final sp = _runSync(['/usr/sbin/sysctl', '-n', 'hw.model']);
  if (sp != null && sp.trim().isNotEmpty) return sp.trim();

  final env = Platform.environment;
  return (env['PROCESSOR_IDENTIFIER'] ?? '').trim().isNotEmpty
      ? env['PROCESSOR_IDENTIFIER']!.trim()
      : currentOs().name;
}

String platformOsVersion() => Platform.operatingSystemVersion;

/// Directory for files we own: identity keys, trust store, transfer staging.
///
/// Distinct from the system temp directory on purpose — a temp directory can be
/// cleared by the OS mid-session, which would silently destroy the device
/// identity and every remembered peer.
Future<Directory> appSupportDir() async {
  if (Platform.isIOS || Platform.isMacOS) {
    return getApplicationSupportDirectory();
  }
  // getApplicationSupportDirectory works on Android/Windows/Linux too, but on
  // Linux it may resolve under the XDG data dir, which is the behaviour we
  // want. Fall back to temp only if it genuinely fails.
  try {
    return await getApplicationSupportDirectory();
  } catch (_) {
    return getTemporaryDirectory();
  }
}

/// Run a short helper binary without throwing. Used only for cosmetic device
/// metadata, so failure must never be fatal.
String? _runSync(List<String> command) {
  try {
    final result = Process.runSync(command[0], command.sublist(1));
    if (result.exitCode != 0) return null;
    final out = (result.stdout as String).trim();
    return out.isEmpty ? null : out;
  } catch (_) {
    return null;
  }
}

/// Version string compiled into the app, from pubspec.
const String kAppVersion = '1.0.0+1';