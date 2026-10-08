/// Wires the four layers together and exposes a single object the UI drives.
///
/// The ordering here is load-bearing and each step can fail independently:
///
///   1. identity   — persisted; if this fails we cannot be identified at all
///   2. store      — where inbound bytes land
///   3. authority  — pairing decisions and the trust store
///   4. transport  — binds a port; the *actual* port may differ from the
///                   preferred one, which is why it is read back
///   5. discovery  — must advertise the port from step 4, not the preferred one
///
/// Starting discovery before the transport is bound is the single easiest way
/// to produce a peer that is visible but unreachable.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:uuid/uuid.dart';

import '../core/constants.dart';
import '../core/contracts.dart';
import '../core/crypto/ed25519_identity.dart';
import '../core/crypto/trust_store.dart';
import '../core/discovery/mdns_discovery.dart';
import '../core/logging.dart';
import '../core/models.dart';
import '../core/network/android_ble.dart';
import '../core/network/android_hotspot.dart';
import '../core/network/assisted_join.dart';
import '../core/network/ble_rendezvous.dart';
import '../core/network/hotspot.dart';
import '../core/network/link_strategy.dart';
import '../core/network/macos_ble.dart';
import '../core/network/manual_pairing.dart';
import '../core/network/network_context.dart';
import '../core/transfer/local_file_store.dart';
import '../core/transfer/peer_api_server.dart';
import '../core/transfer/sender_session.dart';
import '../core/transport/tcp_tls_transport.dart';
import '../ui/device_info.dart';
import '../ui/peer_registry.dart';
import '../ui/transfer_controller.dart';

/// A pairing attempt awaiting the user's confirmation.
class PendingPairing {
  PendingPairing({
    required this.peerName,
    required this.proof,
    required this.link,
    required this.completer,
    required this.isInitiator,
    this.peer,
  });

  /// What to call the other device in the dialog.
  final String peerName;

  /// The code to display. Both devices show the same digits when the
  /// certificates agree, which is the whole point: each user can only detect an
  /// impostor by comparing this value with the other screen.
  final PairingProof proof;

  final PeerLink link;
  final Completer<bool> completer;

  /// True when *we* started the pairing (we dialled and will send the code).
  ///
  /// False when the peer is dialling us. The receiver must still display the
  /// code — without it the receiving user has nothing to compare and the check
  /// degrades to "trust anyone who can reach me".
  final bool isInitiator;

  /// Present only on the initiator, which resolved the peer through discovery.
  final DiscoveredPeer? peer;

  String? error;
}

/// An inbound offer awaiting the user's accept/reject.
class PendingOffer {
  PendingOffer({required this.link, required this.offer});

  final PeerLink link;
  final Offer offer;
  final Completer<bool> completer = Completer<bool>();

  String get peerName => link.remote?.deviceName ?? 'A nearby device';
}

/// Where the app is in its lifecycle, so the UI can explain itself.
enum AppPhase { starting, ready, failed, disposed }

/// Where a user-driven "Direct transfer" attempt has got to.
///
/// A value rather than a set of booleans because these are exclusive states and
/// the UI renders exactly one of them. The terminal states matter most: a
/// failure must say *what* failed so the user can act, rather than leaving a
/// spinner that never resolves.
enum DirectTransferState {
  /// Nothing started; the action is available.
  idle,

  /// Asking the OS to start the hotspot.
  startingHotspot,

  /// The hotspot is up and we are waiting for the other device to join it.
  /// Only reached on the hosting side.
  waitingForJoin,

  /// Another device is trying to join / we are detecting a join.
  joining,

  /// A shared subnet now exists; discovery is running on it.
  ready,

  /// The attempt failed. [AppCoordinator.directTransferError] says why.
  failed,

  /// A BLE rendezvous is advertising and waiting for the other device.
  bleAdvertising,

  /// A BLE rendezvous is scanning for the other device.
  bleScanning,

  /// A connection string is ready to share/enter.
  manualReady,
}

/// True only when the app was built with `--dart-define=AERO_AUTOACCEPT=1`.
///
/// A debug escape hatch that lets automated end-to-end tests accept inbound
/// offers without a human touching a dialog. Compile-time only, deliberately:
/// there is no setting that can turn it on at runtime.
const _autoAccept = bool.fromEnvironment('AERO_AUTOACCEPT');

class AppCoordinator extends ChangeNotifier {
  AppCoordinator({
    this.preferredPort = kPreferredPort,
    LinkStrategy? linkStrategy,
    HotspotProvisioner? hotspotProvisioner,
    HotspotJoiner? hotspotJoiner,
    BleAdvertiser? bleAdvertiser,
    BleScanner? bleScanner,
  })  : _fixedLinkStrategy = linkStrategy,
        _hotspot = hotspotProvisioner ?? _defaultHotspotProvisioner(),
        _joiner = hotspotJoiner ?? _defaultHotspotJoiner(),
        _bleAdvertiser = bleAdvertiser ?? _defaultBleAdvertiser(),
        _bleScanner = bleScanner ?? _defaultBleScanner();

  /// Build the platform's hotspot provisioner. Android hosts; nothing else can.
  static HotspotProvisioner _defaultHotspotProvisioner() {
    if (Platform.isAndroid) return AndroidHotspotProvisioner();
    return const UnsupportedHotspotProvisioner(
      'Only Android can create an Aero hotspot. On a Mac, use the other '
      'device to start one.',
    );
  }

  static HotspotJoiner _defaultHotspotJoiner() => AssistedHotspotJoiner();

  /// Android advertises a BLE rendezvous; nothing else does.
  static BleAdvertiser _defaultBleAdvertiser() {
    if (Platform.isAndroid) return AndroidBleAdvertiser();
    return const UnsupportedBleAdvertiser(
      'Only Android advertises an Aero BLE rendezvous.',
    );
  }

  /// macOS scans for a BLE rendezvous; nothing else does in Phase 2.
  static BleScanner _defaultBleScanner() {
    if (Platform.isMacOS) return MacBleScanner();
    return const UnsupportedBleScanner(
      'Only macOS scans for an Aero BLE rendezvous.',
    );
  }

  final int preferredPort;

  /// An explicit strategy override, used by tests. When null the coordinator
  /// picks a strategy that knows this device's fallback capabilities.
  final LinkStrategy? _fixedLinkStrategy;

  /// Creates a hotspot on the hosting device.
  final HotspotProvisioner _hotspot;

  /// Detects joining a hotspot created by the other device.
  final HotspotJoiner _joiner;

  /// Advertises a BLE rendezvous (Android).
  final BleAdvertiser _bleAdvertiser;

  /// Scans for a BLE rendezvous (macOS).
  final BleScanner _bleScanner;

  /// Whether this device can take part in a BLE rendezvous at all.
  bool get canBleRendezvous => _bleAdvertiser.isSupported || _bleScanner.isSupported;

  /// Decides which transport tier to use.
  LinkStrategy get linkStrategy =>
      _fixedLinkStrategy ??
      Phase3LinkStrategy(
        canHostHotspot: _hotspot.isSupported,
        canBleRendezvous: canBleRendezvous,
      );

  /// The network probe and the tier it produced, for diagnostics.
  NetworkContext? _networkContext;
  NetworkContext? get networkContext => _networkContext;
  TierDecision? _tierDecision;

  /// Why this device is on the transport path it is on.
  ///
  /// The observable contract the fallback work depends on: every real-device
  /// run can be read straight off the log/diagnostics instead of guessed at.
  TierDecision? get tierDecision => _tierDecision;

  AppPhase _phase = AppPhase.starting;
  AppPhase get phase => _phase;

  String? _startupError;
  String? get startupError => _startupError;

  Ed25519Identity? _identity;
  TrustStore? _authority;
  LocalFileStore? _store;
  TcpTlsTransport? _transport;
  MdnsDiscovery? _discovery;
  AeroPeerApi? _api;

  late final PeerRegistry registry = PeerRegistry();
  final List<TransferController> _transfers = [];
  final Map<String, SenderSession> _sessions = {};

  /// Live inbound transfers, keyed by the link they belong to.
  ///
  /// Not searched out of [_transfers] by file id on purpose: the peer chooses
  /// file ids, two sessions may reuse one, and matching the wrong transfer
  /// would display another transfer's progress.
  final Map<PeerLink, TransferController> _inbound = {};

  /// Inbound offers the user has not answered yet.
  final List<PendingPairing> pendingPairings = [];
  final List<PendingOffer> pendingOffers = [];

  // --- Direct transfer (offline fallback) ------------------------------------

  DirectTransferState _directState = DirectTransferState.idle;
  DirectTransferState get directTransferState => _directState;

  String? _directError;
  String? get directTransferError => _directError;

  /// The BLE rendezvous payload this device is advertising, when it is the one
  /// being found (Android). Null otherwise.
  BleRendezvous? _bleRendezvous;
  BleRendezvous? get bleRendezvous => _bleRendezvous;

  /// The peer found via BLE, when this device is the scanner (macOS).
  BleRendezvous? _bleFound;
  BleRendezvous? get bleFound => _bleFound;

  /// The connection string this device displays for manual entry.
  ///
  /// Null until the network is known; built on demand so the address is current.
  ManualConnection? _manualPayload;
  ManualConnection? get manualPayload => _manualPayload;

  /// The most recent manual-parse failure, for the UI to explain.
  String? _manualError;
  String? get manualError => _manualError;

  /// The running hotspot, when this device is hosting one.
  HotspotSession? get hotspot => _hotspot.session;

  /// Whether this device can host a hotspot at all.
  bool get canHostHotspot => _hotspot.isSupported;

  /// Whether this device can join one (the macOS side).
  bool get canJoinHotspot => _joiner.isSupported;

  /// True when the UI should offer the "Direct transfer" action.
  ///
  /// Offered when either side of the interaction is possible, so a Mac shows it
  /// (to join a phone's hotspot) and a phone shows it (to create one).
  bool get directTransferAvailable => canHostHotspot || canJoinHotspot;

  /// True when the UI should offer the BLE rendezvous action.
  bool get bleRendezvousAvailable => canBleRendezvous;

  /// True when the current direct-transfer attempt is a BLE rendezvous rather
  /// than a hotspot, so the UI can show the matching stop button.
  bool get isBleRendezvous =>
      _directState == DirectTransferState.bleAdvertising ||
      _directState == DirectTransferState.bleScanning;

  /// True when the selected tier is a working, implemented fallback or the LAN.
  bool get isOnSharedLanTier => _tierDecision?.tier == TransportTier.sharedLan ||
      _tierDecision?.tier == TransportTier.hotspot;

  /// A sentence describing the direct-transfer state, for the banner.
  String? get directTransferHint {
    if (_directError != null) return _directError;
    final session = _hotspot.session;
    return switch (_directState) {
      DirectTransferState.idle => null,
      DirectTransferState.startingHotspot => 'Starting a direct Wi-Fi hotspot…',
      DirectTransferState.waitingForJoin => session == null
          ? 'Waiting for the other device to join…'
          : 'Hotspot "${session.ssid}" is running. On the Mac, join it and then '
              'it will appear here automatically.',
      DirectTransferState.joining => 'Waiting for the Wi-Fi join to complete…',
      DirectTransferState.ready =>
        'Direct connection established. Devices on this hotspot can now be found.',
      DirectTransferState.bleAdvertising =>
        _bleRendezvous == null
            ? 'Advertising over Bluetooth so the other device can find this one…'
            : 'Bluetooth rendezvous active. The other device can now find this one.',
      DirectTransferState.bleScanning =>
        'Scanning over Bluetooth for the other device…',
      DirectTransferState.manualReady =>
        'Manual connection ready. Share the connection string below, or enter '
            'one from the other device.',
      DirectTransferState.failed => _directError ?? 'Direct transfer failed.',
    };
  }

  PeerInfo? get selfInfo => _selfInfo;
  PeerInfo? _selfInfo;

  int? get boundPort => _transport?.boundPort;

  /// Every transfer, newest first.
  List<TransferView> get transfers =>
      _transfers.reversed.map((t) => t.view).toList(growable: false);

  /// Why discovery cannot work, if it cannot. Distinct from "no peers found".
  String? get discoveryProblem {
    if (_phase == AppPhase.failed) return _startupError;
    final reason = _discovery?.unavailableReason;
    if (reason != null) return reason;
    // A very common, very confusing case: discovery works but the OS denied LAN
    // access, so we advertise and find nobody.
    if (registry.count == 0 && _discovery != null) {
      return 'Searching for devices. If the list stays empty, check that both '
          'devices are on the same Wi-Fi and that Aero has Local Network access '
          'in System Settings → Privacy & Security.';
    }
    return null;
  }

  Map<String, String> get discoveryDiagnostics => _discovery?.diagnostics ?? const {};

  /// The transport-tier decision, for the diagnostics panel.
  ///
  /// Deliberately recomputes the *live* discovery reason rather than echoing the
  /// startup snapshot: at startup there are never any peers, so
  /// [TierReason.noReachablePeers] would always be shown even once a peer
  /// appears. The network-level reason is still the startup one, because the
  /// interface list only changes when the OS tells us and re-probing on every
  /// rebuild would be wasteful.
  Map<String, String> get tierDiagnostics {
    final context = _networkContext;
    final decision = _tierDecision;
    final live = mdnsUnavailableReason(
      _discovery?.unavailableReason,
      registry.count,
    );
    return <String, String>{
      'tier': decision?.tier.label ?? 'not selected',
      'tierRank': '${decision?.tier.rank ?? -1}',
      'tierReason': decision?.reason.id ?? 'none',
      'tierDetail': decision?.detail ?? '',
      'networkReason': context?.reason.id ?? 'not probed',
      'networkSummary': context?.summary ?? 'not probed',
      'lanInterfaces': context == null
          ? 'not probed'
          : (context.lanInterfaces.isEmpty
              ? 'none'
              : context.lanInterfaces.map((i) => i.name).join(', ')),
      'nonShareableInterfaces': context == null
          ? 'not probed'
          : (context.nonShareableInterfaces.isEmpty
              ? 'none'
              : context.nonShareableInterfaces
                  .map((i) => '${i.name}(${i.kind.name})')
                  .join(', ')),
      'liveReason': live.id,
      'directState': _directState.name,
      'hotspot': _hotspot.session?.redacted ?? 'none',
      'canHostHotspot': '$_canHostHotspot',
      'canBleRendezvous': '$canBleRendezvous',
      'bleAdvertising': '${_bleAdvertiser.isAdvertising}',
      'bleRendezvous': _bleRendezvous?.toString() ?? 'none',
      'bleFound': _bleFound?.toString() ?? 'none',
      'manualPayload': _manualPayload?.toString() ?? 'none',
      'manualError': _manualError ?? 'none',
    };
  }

  bool get _canHostHotspot => _hotspot.isSupported;

  // --------------------------------------------------------------------------
  // Lifecycle
  // --------------------------------------------------------------------------

  Future<void> start() async {
    try {
      _identity = await Ed25519Identity.load();
      _authority = TrustStore();
      _store = LocalFileStore();

      // Probe the network before binding anything. This is advisory only - it
      // never gates startup - but it is the first thing the log should say,
      // because "why is the peer list empty?" is answered here more often than
      // anywhere else. The probe cannot throw (see [probeNetworkContext]).
      _networkContext = await probeNetworkContext();
      _tierDecision = linkStrategy.select(_networkContext!);
      coreLog.info(
        'network: ${_networkContext!.reason.id}; '
        'interfaces=[${_networkContext!.interfaces.join(', ')}]',
      );
      coreLog.info('transport tier: ${_tierDecision!.summary}');

      _selfInfo = PeerInfo(
        deviceId: _identity!.deviceId,
        deviceName: platformDeviceName(),
        os: currentOs(),
        osVersion: platformOsVersion(),
        appVersion: kAppVersion,
        publicKey: _identity!.publicKey,
        protocolVersion: kProtocolVersion,
        capabilities: const {
          Capability.send,
          Capability.receive,
          Capability.multiFile,
          Capability.resume,
        },
        nonce: _identity!.freshNonce(),
        port: preferredPort,
      );

      _api = AeroPeerApi(
        selfInfo: () => _selfInfo!,
        store: _store!,
        authority: _authority!,
        onOffer: _approveOffer,
        onProgress: _onInboundProgress,
        onComplete: _onInboundComplete,
        onPairingChallenge: _confirmPairingAsReceiver,
      );

      _transport = TcpTlsTransport(identity: _identity!, port: preferredPort);
      await _transport!.serve(_api!);

      final port = _transport!.boundPort;
      if (port == null) {
        throw AeroException('the transport bound no port');
      }
      if (port != preferredPort) {
        coreLog.warning(
          'Port $preferredPort was unavailable; using $port. Advertising $port.',
        );
      }

      // Advertise the port we actually bound, never the preferred one.
      _selfInfo = _selfInfo!.copyWith(port: port);

      _discovery = MdnsDiscovery();
      registry.attach(_discovery!, selfDeviceId: _identity!.deviceId);
      await _discovery!.start(port: port, self: _selfInfo!);

      _phase = AppPhase.ready;
      coreLog.info(
        'ready: ${_selfInfo!.deviceName} on port $port '
        '(${_identity!.deviceId.substring(0, 8)})',
      );
    } catch (error, stack) {
      _phase = AppPhase.failed;
      _startupError = _explainStartupFailure(error);
      coreLog.severe('startup failed', error, stack);
    }
    notifyListeners();
  }

  /// Turn a raw startup exception into something a user can act on.
  ///
  /// The macOS local-network failure is silent at the OS level, so the only
  /// chance to hint at it is here.
  static String _explainStartupFailure(Object error) {
    if (error is AeroException) return error.message;
    if (error is SocketException) {
      return 'Could not use the network: ${error.osError?.message ?? error.message}. '
          'On macOS, check Local Network access in System Settings → Privacy & Security.';
    }
    return '$error';
  }

  // --------------------------------------------------------------------------
  // Direct transfer (offline fallback)
  // --------------------------------------------------------------------------

  /// User-driven "Direct transfer": stand up or join a hotspot, then rediscover.
  ///
  /// Deliberately never called automatically. Turning on an access point is a
  /// visible, power-hungry, user-consented act, and doing it because a scan came
  /// back empty would be a surprising thing for an app to do on its own.
  ///
  /// On a device that can host (Android) this creates the hotspot. On a device
  /// that can only join (macOS) it waits for the user to join one. Either way the
  /// end state is the same: a shared subnet on which the *existing* discovery and
  /// transport run untouched.
  Future<void> beginDirectTransfer() async {
    if (_phase != AppPhase.ready) {
      _failDirect('Aero is not ready yet.');
      return;
    }
    if (_directState != DirectTransferState.idle &&
        _directState != DirectTransferState.failed &&
        _directState != DirectTransferState.ready) {
      // Already in progress; a second tap must not double-start a radio.
      return;
    }

    if (_hotspot.isSupported) {
      await _startHotspotAndAdvertise();
    } else if (_joiner.isSupported) {
      await _joinPeerHotspot();
    } else {
      _failDirect('This device can neither create nor join an Aero hotspot.');
    }
  }

  /// User-driven "Find over Bluetooth": a BLE rendezvous instead of a hotspot.
  ///
  /// Android advertises; macOS scans. A rendezvous carries only an endpoint or
  /// hotspot credentials, never file bytes, and never authenticates the peer -
  /// the SAS over the resulting IP link still does that. This exists for the
  /// case mDNS cannot reach across (client isolation, blocked multicast) or
  /// when the hotspot credentials themselves need to get to the other device.
  Future<void> beginBleRendezvous() async {
    if (_phase != AppPhase.ready) {
      _failDirect('Aero is not ready yet.');
      return;
    }
    if (_directState == DirectTransferState.bleAdvertising ||
        _directState == DirectTransferState.bleScanning) {
      return;
    }

    if (_bleAdvertiser.isSupported) {
      await _startBleAdvertising();
    } else if (_bleScanner.isSupported) {
      await _scanBleRendezvous();
    } else {
      _failDirect('This device cannot use Bluetooth for a rendezvous.');
    }
  }

  /// Stop any fallback (hotspot or BLE) and return to normal discovery.
  Future<void> endDirectTransfer() async {
    if (_hotspot.isSupported) {
      try {
        await _hotspot.stop();
      } on Object catch (error) {
        coreLog.warning('stopping the hotspot failed', error);
      }
    }
    try {
      await _bleAdvertiser.stop();
      await _bleScanner.stop();
    } on Object catch (error) {
      coreLog.warning('stopping the BLE rendezvous failed', error);
    }
    _bleRendezvous = null;
    _bleFound = null;
    _manualPayload = null;
    _manualError = null;
    _directState = DirectTransferState.idle;
    _directError = null;
    await _reprobeAndRestartDiscovery();
    notifyListeners();
  }

  /// Start advertising a BLE rendezvous (Android).
  Future<void> _startBleAdvertising() async {
    _directState = DirectTransferState.bleAdvertising;
    _directError = null;
    notifyListeners();

    // The payload hands over everything the other device needs to reach us
    // without mDNS: our identity (untrusted, for display/dedup), the nonce that
    // seeds the SAS, and our listening endpoint. Hotspot credentials are added
    // when we are also hosting one, so a scanning Mac can join it directly.
    final session = _hotspot.session;
    final payload = BleRendezvous(
      deviceName: _selfInfo?.deviceName ?? 'A device',
      deviceId: _identity?.deviceId ?? '',
      host: _advertisedAddress(),
      port: _transport?.boundPort,
      nonce: _selfInfo?.nonce,
      hotspotSsid: session?.ssid,
      hotspotPsk: session?.psk,
      os: currentOs().name,
    );

    if (payload.deviceId.isEmpty) {
      _failDirect('Aero is not ready to advertise yet.');
      return;
    }

    try {
      final advertiser = _bleAdvertiser;
      if (advertiser is AndroidBleAdvertiser) {
        // Request the Android 12+ Bluetooth runtime permission before starting,
        // so the failure is a clear prompt rather than a silent no-op.
        final granted = await advertiser.requestPermission();
        if (!granted) {
          _failDirect(
            'Aero needs the Nearby devices permission to advertise over '
            'Bluetooth. Grant it in app settings and try again.',
          );
          return;
        }
      }
      await _bleAdvertiser.start(
        rendezvousId: _shortRendezvousId(payload.deviceId),
        payload: payload,
      );
      _bleRendezvous = payload;
      coreLog.info('BLE rendezvous advertising: $payload');
    } on BleException catch (error) {
      _failDirect(_explainBleError(error));
      return;
    } on Object catch (error) {
      _failDirect('Could not advertise over Bluetooth: $error');
      return;
    }
    notifyListeners();
  }

  /// Scan for a BLE rendezvous (macOS).
  Future<void> _scanBleRendezvous() async {
    _directState = DirectTransferState.bleScanning;
    _directError = null;
    notifyListeners();

    BleRendezvous? found;
    try {
      found = await _bleScanner.scanOnce();
    } on BleException catch (error) {
      _failDirect(_explainBleError(error));
      return;
    } on Object catch (error) {
      _failDirect('Could not scan over Bluetooth: $error');
      return;
    }

    if (found == null) {
      _failDirect(
        'No Aero device was found over Bluetooth. Make sure the other device '
        'has started its Bluetooth rendezvous, then try again.',
      );
      return;
    }

    _bleFound = found;
    coreLog.info('BLE rendezvous found: $found');

    // If the rendezvous carried hotspot credentials, hand them to the joiner so
    // the user can join that network; the assisted-join flow then detects it.
    if (found.hasHotspot) {
      _directState = DirectTransferState.joining;
      notifyListeners();
      final address = await _joiner.awaitJoin(found.hotspotSsid!);
      if (address == null) {
        _failDirect(
          'Found a device over Bluetooth, but did not detect a Wi-Fi join. '
          'Join the hotspot "${found.hotspotSsid}" from Wi-Fi settings, then try again.',
        );
        return;
      }
    }

    // A rendezvous with a direct endpoint needs no join: we can dial it now.
    _directState = DirectTransferState.ready;
    notifyListeners();
    await _reprobeAndRestartDiscovery();
  }

  /// A short, stable handle for the advertisement.
  ///
  /// The advertisement is tiny, so this is a prefix of the device id rather than
  /// the whole thing. It is only for the central to log which attempt it saw;
  /// the full identity arrives over GATT.
  static String _shortRendezvousId(String deviceId) =>
      deviceId.length <= 12 ? deviceId : deviceId.substring(0, 12);

  /// This device's LAN address, for a rendezvous endpoint hint.
  ///
  /// Best-effort: a device with several interfaces has no single answer, and the
  /// scanning side re-checks the address is dialable. Returning null is fine -
  /// the rendezvous then carries only the nonce and (if hosting) hotspot
  /// credentials.
  String? _advertisedAddress() {
    final interfaces = _networkContext?.lanInterfaces ?? const [];
    for (final interface in interfaces) {
      for (final address in interface.addresses) {
        if (!address.contains(':') && !address.startsWith('169.254')) {
          return address;
        }
      }
    }
    return interfaces.isEmpty ? null : interfaces.first.addresses.firstOrNull;
  }

  // --------------------------------------------------------------------------
  // Manual pairing (the last resort)
  // --------------------------------------------------------------------------

  /// Build (or refresh) the connection string this device displays for manual
  /// entry, and enter the manual tier.
  ///
  /// User-driven like every other fallback. This needs no radio, so it is the one
  /// tier that always works - which is why the selector never has to report
  /// "there is nothing we can do".
  void beginManualConnection() {
    if (_phase != AppPhase.ready) {
      _failDirect('Aero is not ready yet.');
      return;
    }

    final payload = buildManualConnection(
      host: _advertisedAddress(),
      port: _transport?.boundPort,
      deviceName: _selfInfo?.deviceName ?? 'A device',
      deviceId: _identity?.deviceId ?? '',
      publicKeyHash: PeerInfo.hashPublicKey(_selfInfo?.publicKey ?? ''),
      os: currentOs().name,
    );

    if (payload == null) {
      // No dialable address means there is genuinely nothing to share: the user
      // needs a network first. Say so rather than displaying a broken string.
      _failDirect(
        'There is no network address to share yet. Connect this device to a '
        'Wi-Fi network — even one with no internet — and try again.',
      );
      return;
    }

    _manualPayload = payload;
    _manualError = null;
    _directState = DirectTransferState.manualReady;
    _directError = null;
    coreLog.info('manual connection ready: ${payload.toUriString()}');
    notifyListeners();
  }

  /// Parse a pasted connection string and dial it.
  ///
  /// Deliberately goes through the *same* `sendTo` path as a discovered peer, so
  /// the pairing code, the trust store, and the whole transfer stack behave
  /// identically. Discovery is bypassed; nothing else is.
  ///
  /// Returns the send outcome so the caller can surface it, or null when the
  /// string could not be parsed (in which case [manualError] explains why).
  Future<SendOutcome?> connectManually(String raw, List<String> paths) async {
    final result = parseManualConnection(raw);
    if (!result.isSuccess) {
      _manualError = result.message;
      coreLog.info('manual connection rejected: ${result.reason?.id} ${result.detail}');
      notifyListeners();
      return null;
    }

    final connection = result.connection!;
    _manualError = null;
    coreLog.info('manual connection parsed: $connection');
    notifyListeners();

    // The manual payload carries no live nonce (it was a point-in-time string),
    // so the peer is represented as a discovered one with a null nonce. The real
    // nonce arrives from `GET /v1/info` during the handshake, which is what the
    // SAS is actually derived from - so nothing here weakens the pairing.
    final peer = DiscoveredPeer(
      info: PeerInfo(
        deviceId: connection.deviceId.isEmpty ? connection.host : connection.deviceId,
        deviceName: connection.deviceName.isEmpty
            ? connection.host
            : connection.deviceName,
        os: aeroOsFromName(connection.os),
        osVersion: '',
        appVersion: '',
        publicKey: '',
        protocolVersion: kProtocolVersion,
        capabilities: const {},
        nonce: '',
        port: connection.port,
        publicKeyHash: connection.publicKeyHash,
      ),
      address: connection.address,
      resolvedAt: DateTime.now(),
    );

    return sendTo(peer, paths);
  }

  /// The connection string to display, when one is ready.
  String? get manualConnectionString => _manualPayload?.toUriString();

  /// Turn a typed BLE failure into a sentence the user can act on.
  static String _explainBleError(BleException error) => switch (error.failure) {
        BleFailure.unsupported =>
          error.message.isEmpty ? 'This device cannot use Bluetooth.' : error.message,
        BleFailure.bluetoothOff =>
          'Bluetooth is turned off. Turn it on and try again.',
        BleFailure.permissionDenied =>
          'Aero needs Bluetooth permission. Grant it in settings and try again.',
        BleFailure.advertiseUnsupported =>
          'This device cannot advertise over Bluetooth LE.',
        BleFailure.scanUnavailable =>
          'Bluetooth scanning is unavailable right now. Try again in a moment.',
        BleFailure.timeout =>
          'The Bluetooth rendezvous timed out. Try again.',
        BleFailure.channelUnavailable =>
          'Bluetooth rendezvous support is not available in this build.',
        BleFailure.generic =>
          'Bluetooth rendezvous failed${error.message.isEmpty ? '' : ': ${error.message}'}.',
      };

  Future<void> _startHotspotAndAdvertise() async {
    _directState = DirectTransferState.startingHotspot;
    _directError = null;
    notifyListeners();

    final HotspotSession session;
    try {
      session = await _hotspot.start();
    } on HotspotProvisionException catch (error) {
      _failDirect(_explainHotspotError(error));
      return;
    } on Object catch (error) {
      _failDirect('Could not start the hotspot: $error');
      return;
    }

    // The AP is up. Our own interface list has not necessarily changed yet on
    // this device (the phone is the AP, it does not "join" itself), so re-probe
    // is about mDNS getting a fresh, correct interface list rather than about a
    // new address appearing.
    _directState = DirectTransferState.waitingForJoin;
    notifyListeners();
    await _reprobeAndRestartDiscovery();

    coreLog.info(
      'direct transfer: hotspot ${session.redacted} is up; waiting for a peer '
      'to join. Share the credentials with the other device.',
    );
  }

  Future<void> _joinPeerHotspot() async {
    _directState = DirectTransferState.joining;
    _directError = null;
    notifyListeners();

    // The joining side has no credentials of its own to start with. The user is
    // shown them by the *other* device and (on macOS) joins through System
    // Settings; we only detect the result. If a session was handed to us out of
    // band (a future QR/manual tier), use its SSID for the wait.
    final target = _hotspot.session?.ssid ?? '';
    final address = await _joiner.awaitJoin(target);

    if (address == null) {
      _failDirect(
        'Did not detect a Wi-Fi join in time. Make sure this device joined the '
        'hotspot the other device is sharing, then try again.',
      );
      return;
    }

    _directState = DirectTransferState.ready;
    notifyListeners();
    await _reprobeAndRestartDiscovery();
    coreLog.info('direct transfer: joined the peer hotspot at $address');
  }

  /// Re-probe the network and restart discovery on whatever link now exists.
  ///
  /// Restarting mDNS is the part that matters: the browser was listening on the
  /// old interface set, and a subnet change is exactly when a stale browser
  /// silently stops reporting peers. The transport is *not* touched - its
  /// listening socket is bound to `anyIPv4`, so it is reachable on the new link
  /// without a rebind.
  Future<void> _reprobeAndRestartDiscovery() async {
    _networkContext = await probeNetworkContext();
    _tierDecision = linkStrategy.select(_networkContext!);
    coreLog.info(
      're-probe: ${_networkContext!.reason.id}; tier=${_tierDecision!.summary}',
    );

    final discovery = _discovery;
    final port = _transport?.boundPort;
    final self = _selfInfo;
    if (discovery == null || port == null || self == null) return;
    try {
      await discovery.stop();
      await discovery.start(port: port, self: self);
      coreLog.info('discovery restarted after the network changed');
    } on Object catch (error, stack) {
      // A restart failure must not lose the tier change: the user can still see
      // the hotspot is up, and the discovery layer reports its own reason.
      coreLog.warning('discovery restart after a network change failed', error, stack);
    }
  }

  /// Re-probe on demand (the refresh button, or after a manual Wi-Fi change).
  Future<void> reprobeNetwork() async {
    if (_phase != AppPhase.ready) return;
    await _reprobeAndRestartDiscovery();
    notifyListeners();
  }

  void _failDirect(String message) {
    _directState = DirectTransferState.failed;
    _directError = message;
    coreLog.warning('direct transfer failed: $message');
    notifyListeners();
  }

  /// Turn a typed hotspot failure into a sentence the user can act on.
  static String _explainHotspotError(HotspotProvisionException error) =>
      switch (error.failure) {
        HotspotFailure.unsupported =>
          error.message.isEmpty ? 'This device cannot create a hotspot.' : error.message,
        HotspotFailure.permissionDenied =>
          'Aero needs the Nearby devices permission to create a hotspot. Grant '
              'it in app settings and try again.',
        HotspotFailure.tetheringDisallowed =>
          'This device is not allowed to share its connection (tethering is '
              'disabled by policy). Try starting the hotspot on the other device.',
        HotspotFailure.noChannel =>
          'No Wi-Fi channel is free to start a hotspot right now. Try again in a moment.',
        HotspotFailure.incompatibleMode =>
          'Wi-Fi is busy with another mode that blocks a hotspot. Turn off any '
              'existing hotspot or Wi-Fi Direct group and try again.',
        HotspotFailure.timeout =>
          'The hotspot did not start in time. Try again.',
        HotspotFailure.alreadyRunning =>
          'A hotspot is already running.',
        HotspotFailure.channelUnavailable =>
          'Hotspot support is not available in this build.',
        HotspotFailure.malformed =>
          'The hotspot started but reported no usable name. Try again.',
        HotspotFailure.generic =>
          'Could not start the hotspot${error.message.isEmpty ? '' : ': ${error.message}'}.',
      };

  @override
  void dispose() {
    _phase = AppPhase.disposed;
    // Releasing the hotspot matters: a LocalOnlyHotspot reservation outlives a
    // simple process teardown on some ROMs, leaving a stray network the user
    // cannot easily turn off. The same applies to a BLE advertisement, which
    // would otherwise keep the phone visible to scanners after the app is gone.
    if (_hotspot.session != null) unawaited(_hotspot.stop());
    unawaited(_bleAdvertiser.stop());
    unawaited(_bleScanner.stop());
    for (final s in _sessions.values) {
      unawaited(s.dispose());
    }
    for (final t in _transfers) {
      t.dispose();
    }
    unawaited(_discovery?.dispose() ?? Future<void>.value());
    unawaited(_transport?.close() ?? Future<void>.value());
    registry.dispose();
    super.dispose();
  }

  // --------------------------------------------------------------------------
  // Sending
  // --------------------------------------------------------------------------

  /// Connect, pair, then send.
  ///
  /// Returns the outcome for the caller to surface. Pairing is interactive, so
  /// this suspends until the user confirms or rejects.
  Future<SendOutcome> sendTo(DiscoveredPeer peer, List<String> paths) async {
    final transport = _transport;
    if (transport == null || _phase != AppPhase.ready) {
      return const SendOutcome.failed('Aero is not ready yet.');
    }

    // A peer that vanished between the list rendering and the tap.
    final target = registry.byId(peer.deviceId);
    if (target == null) {
      return const SendOutcome.failed('That device is no longer available.');
    }

    PeerLink? link;
    try {
      link = await transport.connect(target.address);
    } on PeerException catch (e) {
      return SendOutcome.failed(_connectError(e));
    } on SocketException catch (e) {
      return SendOutcome.failed(
        'Could not reach ${target.info.deviceName}: ${e.osError?.message ?? e.message}',
      );
    } catch (e) {
      return SendOutcome.failed('Could not reach ${target.info.deviceName}: $e');
    }

    // The handshake is the authoritative view of the peer; the TXT record could
    // be stale or forged.
    final authoritative = link.remote;
    if (authoritative != null) {
      registry.enrich(target.deviceId, authoritative);
    }

    try {
      final subject = authoritative ?? target.info;
      if (!subject.isCompatible) {
        return SendOutcome.failed(
          '${subject.deviceName} talks protocol v${subject.protocolVersion}, '
          'this app speaks v$kProtocolVersion.',
        );
      }

      final paired = await _pair(link, target);
      if (!paired) {
        return const SendOutcome.cancelled();
      }

      final files = await _describeFiles(paths);
      if (files.isEmpty) return const SendOutcome.cancelled();

      final controller = TransferController(
        id: const Uuid().v4(),
        peerName: subject.deviceName,
        direction: TransferDirection.sending,
      );
      _addTransfer(controller);
      controller.registerFiles(
        files.map((f) => FileEntry(id: f.id, name: f.name, size: f.size, relPath: f.relPath)).toList(),
        state: TransferState.queued,
      );
      final session = SenderSession(
        link: link,
        reader: _store!,
        store: _store!,
      );
      _sessions[controller.id] = session;

      final subscription = session.progress.listen((p) {
        controller.onBytes(fileId: p.entry.id, cumulativeBytes: p.bytesTransferred, fileTotal: p.entry.size);
      });
      controller.setOutcome(TransferOutcome.transferring);

      final result = await session.send(files);
      await subscription.cancel();

      for (final (id, reason) in result.rejected) {
        controller.addRejected(id, reason);
      }
      controller.markState(
        result.ok ? TransferState.done : TransferState.failed,
      );

      if (result.cancelled) {
        controller.setOutcome(TransferOutcome.cancelled);
        return const SendOutcome.cancelled();
      }
      if (result.ok) {
        controller.setOutcome(TransferOutcome.succeeded);
        return SendOutcome.sent(
          completed: result.completed.length,
          rejected: result.rejected.length,
        );
      }
      controller.setOutcome(
        TransferOutcome.failed,
        errorMessage: result.failures.values.firstOrNull ?? 'The transfer did not complete.',
      );
      return SendOutcome.failed(
        result.failures.values.firstOrNull ?? 'The transfer did not complete.',
      );
    } on PeerException catch (e) {
      // A pairing refusal, a rate limit, or a busy peer arrives as a
      // PeerException from `_pair`. Letting it propagate would reach the UI
      // callback unguarded and tear down the isolate, so it is converted here.
      return SendOutcome.failed(_connectError(e));
    } catch (e) {
      return SendOutcome.failed('The transfer could not start: $e');
    } finally {
      // Released only after the session finishes: closing earlier would abort
      // in-flight requests.
      await link.close();
    }
  }

  static String _connectError(PeerException e) => switch (e.code) {
        ApiError.internal => 'Could not connect — the device may have gone away.',
        ApiError.conflict => 'That device is busy with another transfer.',
        ApiError.rejected => 'The other device declined the pairing.',
        ApiError.sasMismatch => 'Pairing failed: the two devices showed different codes. '
            'Reconnect to get a fresh code.',
        ApiError.sasExpired => 'The pairing code expired. Reconnect to get a new one.',
        ApiError.tooManyAttempts => 'Too many pairing attempts. Wait a minute and try again.',
        ApiError.notPaired => 'The other device is not ready to receive yet.',
        _ => 'Connection failed (${e.code}).',
      };

  /// Run the interactive pairing handshake over [link].
  Future<bool> _pair(PeerLink link, DiscoveredPeer peer) async {
    final local = link.localCertFingerprint;
    final remote = link.remoteCertFingerprint;
    if (remote == null || remote.isEmpty) {
      // Without the peer's certificate we have nothing to derive a code from,
      // and continuing would make the code meaningless as a security check.
      throw PeerException(
        ApiError.internal,
        'the peer did not present a certificate to verify',
      );
    }

    final subject = link.remote ?? peer.info;
    final proof = _authority!.deriveProof(
      localFingerprint: local,
      remoteFingerprint: remote,
      nonce: subject.nonce,
    );


    final completer = Completer<bool>();
    final pending = PendingPairing(
      peerName: subject.deviceName,
      peer: peer,
      proof: proof,
      link: link,
      completer: completer,
      isInitiator: true,
    );
    pendingPairings.add(pending);
    notifyListeners();

    final confirmed = await completer.future;
    pendingPairings.remove(pending);
    notifyListeners();

    if (!confirmed) return false;

    // The server re-derives the code from the nonce and both certificates, so a
    // man in the middle cannot pass this check by echoing our own value back.
    final result = await link.requestJson('POST', Api.pair, body: {
      'confirm': true,
      'proof': {'method': proof.method, 'value': proof.value},
      'nonce': subject.nonce,
    });

    final parsed = PairingResult.fromJson(result);
    if (!parsed.paired) {
      throw PeerException(parsed.error ?? ApiError.sasMismatch, 'the peer refused pairing');
    }

    if (subject.publicKey.isNotEmpty) {
      await _authority!.rememberPeer(deviceId: subject.deviceId, publicKey: subject.publicKey);
    }
    return true;
  }

  /// The user pressed "codes match".
  Future<void> confirmPairing(PendingPairing pending) async {
    if (!pending.completer.isCompleted) pending.completer.complete(true);
  }

  /// The user pressed cancel, or the code did not match.
  Future<void> rejectPairing(PendingPairing pending, {String? reason}) async {
    if (!pending.completer.isCompleted) pending.completer.complete(false);
  }

  /// A peer wants to pair with us and its code checks out cryptographically.
  ///
  /// Our user must still compare the digits on both screens: this is the step
  /// that catches an attacker who terminated both TLS sessions itself, which
  /// certificate verification alone cannot detect. Blocking here blocks the
  /// peer's `POST /v1/pair`, so nothing is written until the user answers.
  Future<bool> _confirmPairingAsReceiver(PeerLink link, PairingProof expected) async {
    if (_autoAccept) {
      coreLog.warning('auto-confirming pairing from ${link.remote?.deviceId} (debug flag)');
      return true;
    }

    final completer = Completer<bool>();
    final pending = PendingPairing(
      peerName: link.remote?.deviceName ?? 'A nearby device',
      proof: expected,
      link: link,
      completer: completer,
      isInitiator: false,
    );
    pendingPairings.add(pending);
    notifyListeners();

    final approved = await completer.future;
    pendingPairings.remove(pending);
    notifyListeners();
    return approved;
  }

  // --------------------------------------------------------------------------
  // Receiving
  // --------------------------------------------------------------------------

  Future<bool> _approveOffer(PeerLink link, Offer offer) async {
    // Headless/test builds can accept without a prompt. Guarded by a
    // compile-time flag and never a runtime option, so it cannot be enabled by
    // data or a stray device.
    var approved = _autoAccept;
    if (approved) {
      coreLog.warning('auto-accepting offer from ${link.remote?.deviceId} (debug flag)');
    } else {
      final pending = PendingOffer(link: link, offer: offer);
      pendingOffers.add(pending);
      notifyListeners();
      approved = await pending.completer.future;
      pendingOffers.remove(pending);
      notifyListeners();
    }

    if (approved) {
      // Registered on BOTH paths. Previously the auto-accept path returned
      // early without creating a controller, so progress callbacks had nothing
      // to update and the receiver's UI stayed empty for a transfer that was
      // actually running.
      final controller = TransferController(
        id: offer.sessionId,
        peerName: link.remote?.deviceName ?? 'A device',
        direction: TransferDirection.receiving,
      );
      controller.registerFiles(offer.files, state: TransferState.accepted);
      _addTransfer(controller);
      // Keyed by link rather than matched out of the whole history by file id:
      // two sessions can legitimately contain the same file id, and matching
      // the wrong one would show another transfer's bytes.
      _inbound[link] = controller;
    }
    return approved;
  }

  void _onInboundProgress(PeerLink link, String fileId, int received, int total) {
    final controller = _inbound[link];
    if (controller == null) return;
    if (!controller.view.files.containsKey(fileId)) return;
    controller.onBytes(fileId: fileId, cumulativeBytes: received, fileTotal: total);
  }

  void _onInboundComplete(PeerLink link, CompletionResult result) {
    final controller = _inbound.remove(link);
    if (controller == null) return;
    controller.markState(result.ok ? TransferState.done : TransferState.failed);
    controller.setOutcome(
      result.ok ? TransferOutcome.succeeded : TransferOutcome.failed,
      errorMessage: result.ok ? null : result.failures.firstOrNull,
    );
  }

  /// The receiving user answered the offer dialog.
  ///
  /// Completing this is what unblocks the `POST /v1/offer` request on the
  /// wire — the sender is waiting on the response, so nothing has been written
  /// to disk yet.
  void respondToOffer(PendingOffer pending, bool accept) {
    if (!pending.completer.isCompleted) pending.completer.complete(accept);
  }

  // --------------------------------------------------------------------------
  // File description + transfer bookkeeping
  // --------------------------------------------------------------------------

  /// Turn picked paths into [LocalFile]s, with sizes read from disk.
  Future<List<LocalFile>> _describeFiles(List<String> paths) async {
    const uuid = Uuid();
    final out = <LocalFile>[];
    for (final path in paths) {
      final type = FileSystemEntity.typeSync(path, followLinks: true);
      if (type == FileSystemEntityType.directory) {
        out.addAll(await _describeDirectory(path));
        continue;
      }
      if (type != FileSystemEntityType.file) continue;
      final stat = File(path).statSync();
      out.add(LocalFile(
        id: uuid.v4(),
        path: path,
        name: File(path).uri.pathSegments.last,
        size: stat.size,
        mtimeMs: stat.modified.millisecondsSinceEpoch,
      ));
    }
    return out;
  }

  Future<List<LocalFile>> _describeDirectory(String root) async {
    const uuid = Uuid();
    final out = <LocalFile>[];
    final rootName = Directory(root).uri.pathSegments.where((s) => s.isNotEmpty).last;
    await for (final entity in Directory(root).list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      final stat = entity.statSync();
      final rel = entity.path.substring(root.length).replaceAll(RegExp(r'^[/\\]+'), '');
      final parts = rel.split(RegExp(r'[/\\]'));
      out.add(LocalFile(
        id: uuid.v4(),
        path: entity.path,
        name: parts.last,
        size: stat.size,
        relPath: '$rootName/${parts.sublist(0, parts.length - 1).join('/')}'.replaceAll(RegExp(r'/$'), ''),
        mtimeMs: stat.modified.millisecondsSinceEpoch,
      ));
    }
    return out;
  }

  void _addTransfer(TransferController controller) {
    _transfers.add(controller);
    controller.addListener(notifyListeners);
    // Bound the history so a long-running session cannot grow without limit.
    while (_transfers.length > 50) {
      final evicted = _transfers.removeAt(0);
      evicted.removeListener(notifyListeners);
      evicted.dispose();
    }
    notifyListeners();
  }

  Future<void> cancelTransfer(String id) async {
    final controller = _transfers.firstWhere((t) => t.id == id, orElse: () => _transfers.first);
    await _sessions[id]?.cancel();
    controller.setOutcome(TransferOutcome.cancelled);
  }

  /// Replace the advertised port, e.g. after a manual override.
  Future<void> refresh() async {
    notifyListeners();
  }

  /// The directory received files land in, when it can be resolved.
  Future<String?> inboxDirectory() async {
    final dest = _store?.destination;
    return dest?.userHint ?? 'Downloads/Aero';
  }

  /// Where finished files go, phrased for a person. Shown in the UI so a user
  /// knows where to look without hunting through the app's sandbox.
  String get receiveLocationHint =>
      _store?.destination?.userHint ?? _pendingReceiveHint;

  String get _pendingReceiveHint => Platform.isAndroid
      ? 'Downloads ▸ Aero'
      : Platform.isIOS
          ? 'Inside the app only'
          : 'Downloads/Aero';

  /// Short label for the diagnostics panel.
  String get receiveDestinationLabel =>
      _store?.destination?.label ?? 'not yet resolved';
}

/// Result of a send attempt, phrased for the UI.
class SendOutcome {
  const SendOutcome.sent({required this.completed, required this.rejected})
      : _message = null,
        isCancelled = false,
        isFailure = false;
  const SendOutcome.cancelled()
      : _message = null,
        completed = 0,
        rejected = 0,
        isCancelled = true,
        isFailure = false;
  const SendOutcome.failed(this._message)
      : completed = 0,
        rejected = 0,
        isCancelled = false,
        isFailure = true;

  final int completed;
  final int rejected;
  final bool isCancelled;
  final bool isFailure;
  final String? _message;

  String? get message => _message;
  bool get isSuccess => !isCancelled && !isFailure && completed > 0;
}

extension<T> on List<T> {
  T? get firstOrNull => isEmpty ? null : first;
}
