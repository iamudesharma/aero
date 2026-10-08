package com.example.aero

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.core.content.ContextCompat
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Advertises a small BLE rendezvous so a scanning Mac can find this device and
 * learn where to reach it - **never to move file bytes**.
 *
 * # The two-part design, and why
 *
 * A legacy BLE advertisement is 31 bytes total, shared with flags and the
 * service UUID. That cannot hold a URL, an SSID, and a passphrase. So:
 *
 *   * the **advertisement** carries only the fixed Aero service UUID plus a
 *     short rendezvous id (a few hex characters);
 *   * a **GATT characteristic** serves the full JSON payload once a central
 *     connects and reads it.
 *
 * This is the standard "advertise enough to be discovered, then use GATT"
 * pattern. Cramming everything into the advertisement is the classic mistake
 * that works on one OS and silently fails on another.
 *
 * # Error contract
 *
 * Failures use `code` values matching Dart's `BleFailure` enum
 * (`bluetooth_off`, `permission_denied`, `advertise_unsupported`,
 * `channel_unavailable`, `generic`). The Dart side maps them directly.
 */
class AeroBleAdvertiser(private val context: Context) {

    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var advertiseCallback: AdvertiseCallback? = null

    /** The JSON payload currently being served over GATT. */
    @Volatile
    private var payload: ByteArray = ByteArray(0)

    private val serviceUuid: UUID = UUID.fromString(SERVICE_UUID)
    private val payloadCharUuid: UUID = UUID.fromString(PAYLOAD_CHAR_UUID)

    /**
     * Whether advertising is possible, and what is missing if not.
     *
     * Mirrors the Dart `BleCapability` shape. `permission` names the runtime
     * permission Android 12+ requires, so the UI can be specific rather than
     * saying "Bluetooth is broken".
     */
    fun capability(): Map<String, Any> {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = manager?.adapter
        val required = requiredPermissions()
        val missing = required.firstOrNull {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }

        val supported = adapter != null &&
            adapter.isEnabled &&
            adapter.isMultipleAdvertisementSupported &&
            missing == null

        val reason = when {
            adapter == null -> "This device has no Bluetooth adapter."
            !adapter.isEnabled -> "Bluetooth is turned off."
            missing != null -> "Aero does not have the $missing permission yet."
            !adapter.isMultipleAdvertisementSupported ->
                "This device cannot advertise over Bluetooth LE."
            else -> ""
        }
        return mapOf(
            "supported" to supported,
            "reason" to reason,
            "permission" to (missing ?: required.firstOrNull() ?: ""),
        )
    }

    /**
     * Start advertising [rendezvousId] and serve [jsonPayload] over GATT.
     *
     * Throws [BleNativeException] with a [`BleFailure`] code on every failure
     * path, so the channel layer can translate one exception type.
     */
    fun start(rendezvousId: String, jsonPayload: String) {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = manager?.adapter
            ?: throw BleNativeException("generic", "This device has no Bluetooth adapter.")
        if (!adapter.isEnabled) {
            throw BleNativeException("bluetooth_off", "Bluetooth is turned off.")
        }
        requiredPermissions().firstOrNull {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }?.let {
            throw BleNativeException("permission_denied", "Aero needs the $it permission.")
        }
        if (!adapter.isMultipleAdvertisementSupported) {
            throw BleNativeException(
                "advertise_unsupported",
                "This device cannot advertise over Bluetooth LE.",
            )
        }

        stop()

        payload = jsonPayload.toByteArray(StandardCharsets.UTF_8)

        // --- GATT server: serves the payload once a central connects ---------
        val server = manager.openGattServer(context, object : BluetoothGattServerCallback() {
            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic?,
            ) {
                val data = payload
                if (characteristic?.uuid != payloadCharUuid) {
                    gattServer?.sendResponse(
                        device, requestId, BluetoothGatt.GATT_FAILURE, offset, null,
                    )
                    return
                }
                // Offset-aware: a central reading a payload longer than one MTU
                // gets several requests, and ignoring `offset` would loop on the
                // first chunk forever.
                val slice = if (offset <= data.size) {
                    data.copyOfRange(offset, data.size)
                } else {
                    ByteArray(0)
                }
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
            }
        })

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic = BluetoothGattCharacteristic(
            payloadCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(characteristic)
        server.addService(service)
        gattServer = server

        // --- Advertisement: service UUID + a short id only -------------------
        val leAdvertiser = adapter.bluetoothLeAdvertiser
            ?: throw BleNativeException(
                "advertise_unsupported",
                "This device cannot advertise over Bluetooth LE.",
            )
        advertiser = leAdvertiser

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(serviceUuid))
            // The rendezvous id rides in the service data so a central can log
            // which attempt it saw, without a connect. Kept tiny on purpose.
            .addServiceData(ParcelUuid(serviceUuid), rendezvousId.toByteArray(StandardCharsets.UTF_8))
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.i(TAG, "advertising started as $rendezvousId")
            }

            override fun onStartFailure(errorCode: Int) {
                val message = when (errorCode) {
                    ADVERTISE_FAILED_ALREADY_STARTED -> "Already advertising."
                    ADVERTISE_FAILED_DATA_TOO_LARGE ->
                        "The rendezvous advertisement is too large for this device."
                    ADVERTISE_FAILED_FEATURE_UNSUPPORTED ->
                        "This device does not support BLE advertising."
                    ADVERTISE_FAILED_INTERNAL_ERROR -> "Internal Bluetooth error."
                    ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "Too many advertisers already."
                    else -> "Advertising failed ($errorCode)."
                }
                Log.w(TAG, "advertise onStartFailure: $message")
            }
        }
        advertiseCallback = callback
        leAdvertiser.startAdvertising(settings, data, callback)
    }

    /** Stop advertising and tear down the GATT server. Safe when not started. */
    fun stop() {
        try {
            advertiseCallback?.let { advertiser?.stopAdvertising(it) }
        } catch (e: Exception) {
            Log.w(TAG, "stopAdvertising failed", e)
        }
        advertiseCallback = null
        advertiser = null
        try {
            gattServer?.clearServices()
            gattServer?.close()
        } catch (e: Exception) {
            Log.w(TAG, "closing the GATT server failed", e)
        }
        gattServer = null
        payload = ByteArray(0)
    }

    /**
     * Runtime permissions this OS version needs to advertise.
     *
     * Android 12+ (API 31) split Bluetooth into `BLUETOOTH_ADVERTISE` /
     * `BLUETOOTH_CONNECT`; before that, advertising needed no runtime grant but
     * a coarse location permission was still requested by some ROMs.
     */
    private fun requiredPermissions(): List<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            emptyList()
        }

    companion object {
        private const val TAG = "AeroBle"
        const val SERVICE_UUID = "a1e0b1e5-1c0d-4f2e-9a3b-6d7c8e9f0a1b"
        const val PAYLOAD_CHAR_UUID = "a1e0b1e5-1c0d-4f2e-9a3b-6d7c8e9f0a1c"
    }
}

/** A BLE failure with a Dart-`BleFailure`-compatible code. */
class BleNativeException(val code: String, message: String) : Exception(message)
