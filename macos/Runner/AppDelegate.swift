import Cocoa
import CoreBluetooth
import FlutterMacOS

/// BLE rendezvous **scanner** (central role) for macOS.
///
/// A sandboxed Mac app is a reliable BLE central, so scanning is the only BLE
/// direction implemented on Apple platforms. The two roles do not need to be
/// symmetric: Android advertises (its peripheral mode is universally supported),
/// macOS scans. Writing a macOS peripheral that can advertise reliably under the
/// sandbox is not something the platform makes dependable, so we do not try.
///
/// # Trust
///
/// Everything this scanner returns is **unauthenticated broadcast**: any device
/// in range can claim any name, id, or endpoint. The Dart side validates every
/// field and the 6-digit SAS still authenticates the peer over the real TLS
/// link. This scanner's only job is to say "a device advertising Aero is here,
/// and here is where it says it can be reached".
///
/// # The 31-byte problem
///
/// A legacy BLE advertisement cannot hold a URL, an SSID, and a passphrase. So
/// the advertisement carries only the Aero service UUID; the full JSON payload
/// is read from a GATT characteristic once connected. This mirrors the Android
/// side exactly.
final class AeroBleBridge: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {

  static let serviceUuid = CBUUID(string: "a1e0b1e5-1c0d-4f2e-9a3b-6d7c8e9f0a1b")
  static let payloadCharUuid = CBUUID(string: "a1e0b1e5-1c0d-4f2e-9a3b-6d7c8e9f0a1c")

  private var central: CBCentralManager!
  private var pending: FlutterResult?
  private var timeoutWork: DispatchWorkItem?
  private var target: CBPeripheral?
  private var buffer = Data()
  private var finished = false

  /// Callbacks waiting for the radio to reach a decided state.
  ///
  /// `CBCentralManager` powers up asynchronously, so an immediate `capability()`
  /// (or scan) can land while the state is still `.unknown`/`.resetting`. Reading
  /// that as "unsupported" would be wrong, and returning an error from a scan
  /// would be user-visible noise for something that resolves in a moment. So
  /// callers that need an answer wait, briefly, for a terminal state.
  private var stateWaiters: [(CBManagerState) -> Void] = []

  override init() {
    super.init()
    central = CBCentralManager(delegate: self, queue: .main)
  }

  /// Run [body] once the radio has reached a non-transient state.
  ///
  /// Transient states ([.unknown], [.resetting]) are waited through; everything
  /// else ([.poweredOn], [.poweredOff], [.unauthorized], [.unsupported]) is a
  /// real answer and is delivered immediately.
  private func whenDecided(_ body: @escaping (CBManagerState) -> Void) {
    if !isTransient(central.state) {
      body(central.state)
      return
    }
    stateWaiters.append(body)
  }

  private func isTransient(_ state: CBManagerState) -> Bool {
    state == .unknown || state == .resetting
  }

  /// Whether the radio is available, and why not if it is not.
  func capability() -> [String: Any] {
    switch central.state {
    case .poweredOn:
      return ["supported": true, "reason": "", "permission": "Bluetooth"]
    case .poweredOff:
      return ["supported": false, "reason": "Bluetooth is turned off.", "permission": "Bluetooth"]
    case .unauthorized:
      return [
        "supported": false,
        "reason": "Aero does not have Bluetooth permission. Grant it in System Settings → Privacy & Security → Bluetooth.",
        "permission": "Bluetooth",
      ]
    case .unsupported:
      return ["supported": false, "reason": "This Mac has no Bluetooth LE radio.", "permission": "Bluetooth"]
    default:
      return ["supported": false, "reason": "Bluetooth is still starting up.", "permission": "Bluetooth"]
    }
  }

  /// Scan for `timeoutMs`; complete with the first rendezvous payload or nil.
  ///
  /// Nil is a normal outcome (nobody advertising yet), not an error. Only a
  /// radio problem is reported as a FlutterError.
  func scan(timeoutMs: Int, result: @escaping FlutterResult) {
    if pending != nil {
      result(FlutterError(code: "scan_unavailable", message: "A scan is already running.", details: nil))
      return
    }

    // Wait out the transient power-up state before deciding, so an early scan is
    // not misreported as "Bluetooth is off".
    whenDecided { [weak self] state in
      guard let self else { return }
      guard state == .poweredOn else {
        let cap = self.capability()
        result(FlutterError(
          code: state == .unauthorized ? "permission_denied" : "bluetooth_off",
          message: cap["reason"] as? String ?? "Bluetooth is unavailable.",
          details: nil
        ))
        return
      }

      self.pending = result
      self.finished = false
      self.buffer = Data()
      self.target = nil

      // `nil` services would scan for everything; we only care about Aero.
      self.central.scanForPeripherals(withServices: [AeroBleBridge.serviceUuid], options: nil)

      let work = DispatchWorkItem { [weak self] in
        self?.finish(nil)
      }
      self.timeoutWork = work
      DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(timeoutMs), execute: work)
    }
  }

  /// Capability, but only after the radio has settled.
  ///
  /// The async variant is what the channel should call; the sync
  /// [capability] remains for internal use once a state is known.
  func capabilityWhenReady(_ result: @escaping FlutterResult) {
    whenDecided { [weak self] _ in
      result(self?.capability() ?? ["supported": false, "reason": "Bluetooth is unavailable."])
    }
  }

  func stopScan() {
    central.stopScan()
    finish(nil)
  }

  /// Complete the outstanding scan exactly once.
  private func finish(_ value: [String: Any]?) {
    guard !finished else { return }
    finished = true
    timeoutWork?.cancel()
    timeoutWork = nil
    central.stopScan()
    let result = pending
    pending = nil
    target = nil
    result?(value)
  }

  // MARK: - CBCentralManagerDelegate

  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    // Deliver any caller that was waiting for a decided state. Done on every
    // update, so a transition into a decided state releases the waiters, and a
    // further transition (e.g. the user turns Bluetooth off) is observed by
    // nothing that has already been answered.
    guard !isTransient(central.state) else { return }
    let waiters = stateWaiters
    stateWaiters = []
    for waiter in waiters {
      waiter(central.state)
    }
  }

  func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi RSSI: NSNumber
  ) {
    // One candidate at a time: connect, read the payload, and only then decide.
    // Grabbing the first advertiser avoids a stampede on a busy network.
    guard target == nil else { return }
    target = peripheral
    peripheral.delegate = self
    central.connect(peripheral, options: nil)
  }

  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    peripheral.discoverServices([AeroBleBridge.serviceUuid])
  }

  func centralManager(
    _ central: CBCentralManager,
    didFailToConnect peripheral: CBPeripheral,
    error: Error?
  ) {
    // A failed connect is not fatal: reset and keep scanning until the timeout.
    target = nil
    central.scanForPeripherals(withServices: [AeroBleBridge.serviceUuid], options: nil)
  }

  // MARK: - CBPeripheralDelegate

  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
    guard let services = peripheral.services else { return }
    for service in services where service.uuid == AeroBleBridge.serviceUuid {
      peripheral.discoverCharacteristics([AeroBleBridge.payloadCharUuid], for: service)
    }
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didDiscoverCharacteristicsFor service: CBService,
    error: Error?
  ) {
    guard let characteristics = service.characteristics else { return }
    for characteristic in characteristics where characteristic.uuid == AeroBleBridge.payloadCharUuid {
      buffer = Data()
      peripheral.readValue(for: characteristic)
    }
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didUpdateValueFor characteristic: CBCharacteristic,
    error: Error?
  ) {
    guard characteristic.uuid == AeroBleBridge.payloadCharUuid else { return }
    guard let data = characteristic.value else { return }
    buffer.append(data)

    // The payload can be longer than one MTU, so reads may arrive in pieces.
    // We stop at the first complete JSON object; a read that never completes is
    // caught by the scan timeout.
    guard let json = try? JSONSerialization.jsonObject(with: buffer) as? [String: Any] else {
      // Ask for the next chunk; an offset-aware read is what the Android GATT
      // server serves.
      peripheral.readValue(for: characteristic)
      return
    }

    central.cancelPeripheralConnection(peripheral)
    finish(json)
  }
}

@main
class AppDelegate: FlutterAppDelegate {
  private var bleBridge: AeroBleBridge?
  private var bleChannel: FlutterMethodChannel?

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    // Register the BLE rendezvous channel on the main binary messenger. Done
    // here rather than in a plugin so the whole BLE surface lives in the app.
    guard let controller = mainFlutterWindow?.contentViewController as? FlutterViewController else {
      return
    }
    let bridge = AeroBleBridge()
    bleBridge = bridge
    let channel = FlutterMethodChannel(
      name: "aero/ble",
      binaryMessenger: controller.engine.binaryMessenger
    )
    bleChannel = channel
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "bleCapability":
        bridge.capabilityWhenReady { value in result(value) }
      case "scanForRendezvous":
        let args = call.arguments as? [String: Any]
        let timeoutMs = args?["timeoutMs"] as? Int ?? 20000
        bridge.scan(timeoutMs: timeoutMs, result: result)
      case "stopScan":
        bridge.stopScan()
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    super.applicationDidFinishLaunching(notification)
  }
}
