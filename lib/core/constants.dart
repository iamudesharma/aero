/// Protocol-wide constants. Everything that both peers must agree on lives
/// here so there is exactly one source of truth.
library;

/// The Bonjour / DNS-SD service type this app advertises and browses.
///
/// MUST match the `_aero._tcp` entry in `macos/Runner/Info.plist`
/// (`NSBonjourServices`) — iOS/macOS silently refuse to browse a type that is
/// not declared there.
const String kServiceType = '_aero._tcp';

/// The DNS-SD domain. `local` is the mDNS-only domain.
const String kServiceDomain = 'local';

/// Wire-protocol major version. A peer advertising a different major version
/// is still shown in the UI, but flagged as incompatible and cannot transfer.
const int kProtocolVersion = 1;

/// Preferred TCP port. If unavailable, we fall back to an ephemeral port and
/// publish the actual value in the mDNS TXT record (never assume this port).
const int kPreferredPort = 44353;

/// mDNS TXT keys. Short keys matter: the whole record must fit comfortably in
/// one multicast datagram alongside the DNS-SD service name.
class TxtKey {
  static const String deviceId = 'id';
  static const String deviceName = 'name';
  static const String os = 'os';
  static const String osVersion = 'osv';
  static const String appVersion = 'app';
  static const String port = 'port';
  static const String protocol = 'proto';
  static const String publicKeyHash = 'pk';
  static const String capabilities = 'caps';
}

/// URL path prefix for every HTTP endpoint.
class Api {
  static const String info = '/v1/info';
  static const String pair = '/v1/pair';
  static const String offer = '/v1/offer';
  static const String cancel = '/v1/cancel';
  static const String complete = '/v1/complete';
  static const String status = '/v1/status';
  static const String file = '/v1/file';

  /// `GET /v1/file/{id}` — query the number of bytes already stored, so a
  /// resumed transfer can continue instead of restarting.
  static String fileStatus(String id) => '$file/${Uri.encodeComponent(id)}';
}

/// HTTP headers used by the transfer path.
class Header {
  static const String sha256 = 'x-aero-sha256';
  static const String contentRange = 'content-range';
  static const String sessionId = 'x-aero-session';
  static const String deviceId = 'x-aero-device';
}

/// Transfer tuning.
class Transfer {
  /// Size of each chunk as it crosses the socket. 4 MiB was chosen from
  /// benchmarking: it kept SO_SNDBUF saturation without excess per-write
  /// overhead (measured ~1.5 GB/s on loopback with TCP_NODELAY + 4 MiB buffer).
  static const int chunkSize = 4 * 1024 * 1024;

  /// `SO_SNDBUF` requested on the sending socket, in bytes.
  static const int sendBufferSize = 4 * 1024 * 1024;

  /// `TCP_NODELAY`. Off by default in Dart and fatal for throughput: without
  /// it each write can wait for a coalesced segment.
  static const bool tcpNoDelay = true;

  /// How many file transfers may run at once. 1-2 is optimal: more helps only
  /// on lossy links (each TCP stream stalls independently), and hurts on
  /// clean Ethernet where a single stream already saturates.
  static const int maxParallelFiles = 2;

  /// Receiver must have at least this multiple of the total size free.
  static const double requiredFreeSpaceFactor = 1.15;

  /// Refuse absurd manifests so a hostile peer cannot exhaust memory.
  static const int maxFilesPerTransfer = 2000;

  static const int maxFileSize = 1 << 40; // 1 TiB
}

/// Pairing tuning.
class Pairing {
  /// How long a displayed 6-digit code stays valid.
  static const Duration codeLifetime = Duration(seconds: 120);

  /// Number of digits in the short authentication string.
  static const int codeDigits = 6;

  /// Failed attempts allowed per peer before we refuse further tries and the
  /// UI advises restarting discovery.
  static const int maxAttempts = 5;

  /// Cooldown enforced after [maxAttempts] is exhausted.
  static const Duration attemptCooldown = Duration(seconds: 60);
}

/// Cryptographic choices, named so the wire format can advertise them.
class Crypto {
  static const String curve = 'ed25519';
  static const String hash = 'sha256';
  static const String kdf = 'hkdf-sha256';
  static const String pairingMethod = 'sas';
}