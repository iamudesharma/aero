# Aero

**Offline peer-to-peer file transfer between nearby devices — no internet, no
mobile data, no accounts.**

Aero transfers files between nearby devices with **no internet and no mobile
data**. Devices find each other over the local network using mDNS/DNS-SD, prove
to each other that they are really talking to each other with a 6-digit code,
then stream bytes directly peer-to-peer over TLS.

Built with Flutter (macOS first, Android validated on real hardware).

## Architecture

Four layers, each behind an interface so a concrete platform only ever supplies
an adapter:

```
4. App protocol    HTTP/1.1 over TLS: /v1/info, /v1/pair, /v1/offer, /v1/file
3. Session & crypto ephemeral Ed25519 cert -> 6-digit SAS -> TLS -> trust store
2. Discovery        mDNS _aero._tcp, TXT carries id/name/os/port/caps
1. Transport        TLS over TCP   (pluggable: QUIC, WebRTC later)
0. Capability       Tier ladder: shared LAN -> hotspot -> BLE -> manual
                    (Wi-Fi Direct / Wi-Fi Aware are macOS<->Android incompatible)
```

### Why this combination

The research behind these choices, in short:

- **mDNS is the only portable discovery mechanism.** Wi-Fi Direct and Wi-Fi
  Aware are Android-only (Apple exposes Wi-Fi Aware on iOS but not macOS, behind
  a restricted entitlement). MultipeerConnectivity is deprecated as of Xcode 27.
  `bonsoir` wraps each OS's native Bonjour implementation.
- **Using the existing Wi-Fi is *faster* than creating a P2P link.** A shared
  LAN gives 100-600+ Mbit/s, while Wi-Fi Direct measures 11-45 Mbit/s,
  Nearby Connections caps at 31.7 Mbit/s, and Apple peer-to-peer Wi-Fi tops out
  around 45-50 MB/s. P2P link APIs are therefore reserved for the "no shared
  network" case.
- **TLS is for confidentiality, the 6-digit code is for authentication.** A
  self-signed ephemeral certificate defeats eavesdroppers but not an active
  man-in-the-middle, who would present its own certificate. The code is derived
  from both certificate fingerprints plus a fresh per-session nonce, so an
  attacker's transcript necessarily produces different digits. The digits carry
  no exploitable entropy of their own: they are a truncation of a hash over a
  256-bit secret, so they cannot be ground offline.
- **Plain TCP, not QUIC.** `dart:io` has no HTTP/2 or HTTP/3, and on a LAN where
  we control both endpoints QUIC's advantages (NAT traversal, connection
  migration) do not apply. It sits behind the transport interface for later.

## Current status

The full stack **works and is verified on real hardware** — macOS against a
Xiaomi M2007J17I (Android 12 / API 31):

- identity loads and persists; a fresh ECDSA P-256 session certificate is issued
  per run
- the transport binds `44353` (or an ephemeral port, correctly advertised)
- the app advertises `This Mac._aero._tcp.local.` and is discoverable from
  another process, with a complete TXT record:
  `id`, `name`, `os`, `osv`, `app`, `proto`, `port`, `caps`, `pk`
- a second process discovers it, resolves it to a dialable address, and can
  complete the TLS handshake
- two full stacks pair and transfer real files (single, multi-file, 20 MiB
  multi-chunk, folders, resume, refusal) over real TLS sockets
- **macOS → Android** and **Android → macOS** transfers complete over the shared
  LAN and land byte-for-byte correct in `Downloads/Aero` on each side
- the Android **hotspot** starts on the real device (`startLocalOnlyHotspot`),
  the tier selector picks `HOTSPOT_REQUIRED`, and the reservation releases
  cleanly on stop and restarts
- Android **BLE advertising** comes up on the real radio
  (`BluetoothLeAdvertiser` + GATT server), holds, stops, and restarts

The Android hotspot and BLE halves were validated on-device with
`integration_test/android_hotspot_test.dart` and
`integration_test/android_ble_test.dart`.

### Offline fallback (no shared network)

When no shared subnet exists, a **Direct transfer** action lets the user stand up
a link without a router:

- **Android** creates a `LocalOnlyHotspot` (native `aero/direct` channel,
  `WifiManager.startLocalOnlyHotspot`). It is a real access point with no
  internet.
- **macOS** joins that hotspot as an ordinary Wi-Fi client. A sandboxed Mac app
  cannot change the system's Wi-Fi association, so this is *assisted*: the app
  shows the SSID and passphrase, offers copy, and polls for the resulting join.
- Once both devices share the hotspot subnet, **every existing layer runs
  unchanged** — mDNS discovery, TLS, the 6-digit SAS, and the file transfer.

The tier ladder is chosen by `LinkStrategy` and logged with stable identifiers
(`LAN_AVAILABLE`, `NO_SHARED_SUBNET`, `HOTSPOT_REQUIRED`, `BLE_RENDEZVOUS`, …) so
a real-device run explains itself. A usable LAN always wins; `NO_REACHABLE_PEERS`
(an empty list on a good network) never triggers a fallback.

### BLE rendezvous

When the two devices share no subnet and cannot host a hotspot — or when mDNS
cannot reach across (guest Wi-Fi client isolation, blocked multicast) — a **Find
over Bluetooth** action rendezvouses over BLE:

- **Android advertises** (`BluetoothLeAdvertiser` + a GATT server); **macOS
  scans** (`CBCentralManager`). The roles are asymmetric on purpose: Android's
  peripheral mode is universally supported, a sandboxed Mac is a reliable
  central, and pretending otherwise would mean writing a peripheral that cannot
  advertise dependably.
- The advertisement carries only the Aero service UUID (a legacy advertisement is
  31 bytes); the full payload is read over GATT. That payload carries an endpoint
  or hotspot credentials — **never file bytes**. BLE at ~90–156 kbit/s would be
  catastrophic for data.
- The payload is **untrusted broadcast**, treated exactly like an mDNS TXT record:
  every field is validated and capped, and the six-digit SAS still authenticates
  the peer over the real TLS link.

### Manual pairing (the last resort)

When even BLE is blocked — some vendor ROMs (MIUI/HyperOS, ColorOS, vivo) ship
their own LAN and Bluetooth switches that ignore Android permissions entirely —
a **Connect manually** card exchanges a compact connection string:

```
aero://connect?host=192.168.1.5&port=44353&name=Mac&id=…&os=macos
```

- Needs **no radio, no multicast, and no permission** — only the user reading one
  screen and entering it on the other. That is why the ladder always has a bottom
  rung and the selector can never report "there is nothing we can do".
- The string yields a `PeerAddress` that goes through the **same `sendTo` path**
  as a discovered peer: same pairing code, same trust store, same transfer stack.
  Discovery is bypassed; nothing else is.
- Typed input is **untrusted**: the address must be a dialable IP literal (no
  hostname, no loopback, no wildcard), the port must be in range, and every field
  is capped and stripped. A payload pointing at an attacker is still defeated by
  the SAS mismatch the user sees.
- The payload format is a UTF-8 `aero://` string, so the manual tier is
  shareable two ways: as **typed/copied text** and as a **rendered QR code**
  (`lib/ui/qr_code.dart`, using the pure-Dart `qr` package — generation only,
  no native code). The same `encodeManualPayload` / `decodeManualPayload`
  helpers are the single definition of the wire format, and a QR that renders is
  asserted to decode back through the real parser.
- Scanning is deliberately **not** built yet: it needs camera access and native
  code on every platform, which is a much larger commitment. Typing the string
  still works, so the QR is purely additive.

Every tier therefore ends in the same place: **secure peer verification → direct
encrypted file transfer** over the unchanged TLS/TCP stack.

### Receive-path hardening

The fallback tiers exist for constrained situations, so the receiver is
defensive about what it is willing to accept:

- **Structural refusals happen before the user is prompted.** An offer that is
  too large, malformed, or over the file-count cap is answered without ever
  showing the accept dialog — prompting someone to approve a transfer and then
  refusing it on a rule we could have checked first makes the app look broken.
- **Free space is checked up front on desktop.** `dart:io` has no `statvfs`, so
  macOS/Linux/Windows shell out to `df -k -P` (and `wmic` on Windows); mobile
  returns "unknown", where `stage()`'s preallocation is the guard. A parse
  failure returns *unknown* rather than a guess, because a wrong answer would
  accept an offer that cannot be stored.
- **A full-length `.part` leftover is discarded, not trusted.** A process that
  died mid-write leaves a torn file whose length can equal the declared size;
  resuming from it would skip every byte and fail the digest check much later
  with a confusing error, so it is restarted.
- **Name collisions are unique-suffixed** (`probe (1).bin`, …), verified
  end-to-end on both devices — a transfer never silently overwrites an existing
  file.

Layer 0 (Wi-Fi Direct / Wi-Fi Aware) is deliberately not built: the two
platforms do not interoperate (see the research note above). The offline
fallbacks are the hotspot, BLE-rendezvous, and manual tiers described below. Web
is not started beyond the analysis in the research phase.

### Verification

```sh
flutter analyze                      # clean
flutter test                         # 458 tests
flutter test integration_test/mdns_discovery_test.dart -d macos   # real engine
flutter test integration_test/macos_ble_scan_test.dart -d macos   # real CoreBluetooth scan
flutter test integration_test/android_hotspot_test.dart -d <android>  # real hotspot
flutter test integration_test/android_ble_test.dart -d <android>      # real BLE advertise
TGT=192.168.1.25 flutter test tool/manual_connect_probe_test.dart     # real manual dial
```

The integration test is deliberately **not** part of `flutter test`: bonsoir's
Darwin backend reaches mDNSResponder over a real `FlutterMethodChannel`, which
does not exist in the unit-test VM. Advertising and browsing are therefore
untestable without the engine.

### Findings worth knowing before touching this code

**Dart's TLS client cannot use Ed25519 certificates.** Verified directly: an
Ed25519 certificate loads, binds, and then every handshake dies with
`HandshakeException: Connection terminated during handshake`, while ECDSA P-256
succeeds with otherwise identical code. Dart's bundled BoringSSL does not
advertise `ed25519` in `signature_algorithms`. A Dart TLS *server* serves
Ed25519 fine — it is specifically the client. So Ed25519 stays the
device-identity algorithm (used directly, no TLS), and the per-session transport
certificate is ECDSA P-256. `SessionCredentials.signatureAlgorithm` records
which. Note that `package:cryptography` has **no working pure-Dart ECDSA** —
`Ecdsa.p256()` resolves to `DartEcdsa`, whose `newKeyPair`/`sign` throw
`UnimplementedError` under `flutter test` — so `ephemeral_certificate.dart`
implements P-256 and ECDSA-SHA256 directly.

**`startLocalOnlyHotspot` needs `CHANGE_WIFI_STATE`, not just location.**
Found on the real device, not in a unit test: with the permission missing, the
call fails as `permission_denied` and reads like a device limitation
(`WifiService: Neither user nor current process has
android.permission.CHANGE_WIFI_STATE`) rather than a manifest omission. It is a
normal install-time permission, so declaring it in `AndroidManifest.xml` is the
whole fix. This is exactly the class of bug the on-device probe exists to catch.

**A cellular interface is not a LAN.** The network probe used to treat any
non-loopback interface with a dialable address as a shared-LAN candidate, which
counts `rmnet_data1`. A phone on mobile data has a real address there, but it
sits behind the carrier's NAT and mDNS cannot cross it — so the app would report
`LAN_AVAILABLE` on a device with no Wi-Fi and the peer list would stay empty
forever with no explanation. `network_context.dart` now classifies interfaces
(`wifi`, `ethernet`, `cellular`, `vpn`, `loopback`, `other`) and only
shared-link-capable kinds count; an *unrecognised* name falls back to `other`,
which **is** a candidate, because a false positive costs one doomed dial while a
false negative could hide a real network.

**macOS registration does not open a socket in your process.** mDNS goes through
`mDNSResponder` over XPC, so `lsof -p <pid> | grep UDP` showing nothing is
**not** evidence of failure — a trap worth avoiding when debugging. Use
`dns-sd -B _aero._tcp local.` and `dns-sd -L "<name>" _aero._tcp local.` instead.

The pairing code is derived from the two certificate fingerprints, so switching
the transport curve changed no pairing logic: both sides still derive the same
six digits, and a man in the middle still cannot.

## Platform requirements

These are not optional. On macOS especially, a missing entry fails **silently**:
no prompt, no error, no Settings entry, just an empty peer list.

### macOS

Already configured in this repo:

- `macos/Runner/DebugProfile.entitlements` and `Release.entitlements` both need
  `com.apple.security.network.client` and `com.apple.security.network.server`.
  Flutter's template ships neither in Release.
- `macos/Runner/Info.plist` needs `NSLocalNetworkUsageDescription` and
  `NSBonjourServices` containing `_aero._tcp`.

Verify after changing entitlements:

```sh
codesign -d --entitlements - build/macos/Build/Products/Release/aero.app
```

Developer ID signing and notarisation are needed for distribution, not for
local LAN use.

### iOS

`NSLocalNetworkUsageDescription` + `NSBonjourServices`. The user is prompted on
first LAN access.

### Android

- `targetSdk 33+`: `NEARBY_WIFI_DEVICES` runtime permission.
- `targetSdk 37+` (Android 17): `ACCESS_LOCAL_NETWORK` is now **required**, or
  every local socket fails with `SocketException`. The alternative is the system
  discovery picker, which needs no permission.
- `CHANGE_WIFI_MULTICAST_STATE` to receive mDNS on older releases.
- Vendor ROMs (MIUI/HyperOS, ColorOS, vivo) ship their own per-app LAN switches
  that ignore Android permissions entirely.

### Windows

Firewall prompt on first inbound connection. `privateNetworkClientServer`
capability if packaged as MSIX. Package identity is *not* required for the WinRT
Wi-Fi Direct namespaces.

### Linux

Requires a running Avahi daemon and an accessible D-Bus session bus. Wi-Fi
Direct is effectively unavailable; LAN mode only.

### Web

Sender-only. A page can open connections but cannot listen, so the web build can
never be the discovering receiver. No LAN discovery API exists in any browser
(W3C Network Service Discovery is a discontinued 2017 note; `chrome.mdns` died
with Chrome Apps). Additionally, Local Network Access is secure-context-only
(Chrome 142+, Firefox 151+, unimplemented in Safari), and Firefox/Safari cannot
save to a user-chosen directory.

## Commands

```sh
flutter pub get
flutter analyze
flutter test
flutter run -d macos
```

Diagnostics are available in-app from the toolbar (bug icon). They answer
"why is the peer list empty?", which is otherwise indistinguishable from "no
one else is running the app".

## Project structure

```
lib/
  core/
    network/       tier ladder: link_strategy, network_context (interface
                   classification), hotspot, android_hotspot, ble_rendezvous,
                   android_ble, macos_ble, manual_pairing, assisted_join
    transport/     tcp_tls_transport (real TLS over TCP on 44353)
    crypto/        ed25519 identity, ephemeral ECDSA P-256 cert, SAS, trust store
    transfer/      peer_api_server (/v1), sender_session, local_file_store,
                   receive_destination (Downloads/Aero, collision-suffixed)
  app/             app_coordinator — wires every tier, discovery, and pairing
  ui/              home_page (tier cards), diagnostics_view, pairing_dialog,
                   qr_code (manual-tier QR renderer)
android/app/src/main/kotlin/…/   MainActivity (hotspot) + AeroBleAdvertiser
macos/Runner/AppDelegate.swift   CoreBluetooth central bridge
integration_test/  real-engine / real-device probes (mDNS, BLE, hotspot)
tool/              real-socket probes for manual + cross-device transfers
```

Only `android/` and `macos/` platform folders are present; the others are
future targets described in the platform requirements above.

## License

No license has been chosen yet.