package com.example.aero

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * The native half of Aero's offline fallback.
 *
 * Wraps [WifiManager.startLocalOnlyHotspot] so Dart can turn the phone into an
 * access point with no internet - the one supported way to give a macOS and an
 * Android device a shared subnet when no router exists.
 *
 * # Why this is hand-written rather than a plugin
 *
 * The maintained Flutter Wi-Fi packages wrap `WifiNetworkSpecifier` (joining) or
 * ordinary tethering, not `startLocalOnlyHotspot`. The surface we need is three
 * calls, so owning it is less risk than depending on a wrapper we would have to
 * patch.
 *
 * # Error contract
 *
 * Every failure is reported with `code` set to exactly one of the identifiers in
 * Dart's `HotspotFailure` enum (`permission_denied`, `tethering_disallowed`,
 * `no_channel`, `incompatible_mode`, `generic`, `timeout`, `malformed`). The Dart
 * side maps the code directly rather than sniffing the message, so these strings
 * are a contract and must not drift.
 *
 * # Lifecycle
 *
 * The reservation is held for the life of the AP. It must be explicitly closed
 * or the network lingers on some ROMs; [onDestroy] is the backstop, but Dart
 * calls `stopHotspot` on dispose as the primary path.
 */
class MainActivity : FlutterActivity() {

    private var channel: MethodChannel? = null
    private var bleChannel: MethodChannel? = null
    private var reservation: WifiManager.LocalOnlyHotspotReservation? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    /** BLE rendezvous advertiser; created lazily on first use. */
    private var bleAdvertiser: AeroBleAdvertiser? = null

    /** A pending `startHotspot`/`requestPermission` outstanding while the OS prompts. */
    private var permissionCallback: ((Boolean) -> Unit)? = null
    private var blePermissionCallback: ((Boolean) -> Unit)? = null
    private val permissionRequestCode = 4711
    private val blePermissionRequestCode = 4712

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val ch = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        channel = ch
        ch.setMethodCallHandler { call, result ->
            when (call.method) {
                "capability" -> result.success(capability())
                "requestPermission" -> requestHotspotPermission(result)
                "startHotspot" -> startHotspot(result)
                "stopHotspot" -> {
                    stopHotspot()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }

        val ble = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BLE_CHANNEL)
        bleChannel = ble
        ble.setMethodCallHandler { call, result ->
            when (call.method) {
                "bleCapability" -> result.success(bleAdvertiser().capability())
                "requestBlePermission" -> requestBlePermission(result)
                "startAdvertising" -> {
                    val id = call.argument<String>("rendezvousId") ?: ""
                    val payload = call.argument<String>("payload") ?: "{}"
                    try {
                        bleAdvertiser().start(id, payload)
                        result.success(null)
                    } catch (e: BleNativeException) {
                        result.error(e.code, e.message, null)
                    } catch (e: SecurityException) {
                        result.error("permission_denied", e.message, null)
                    } catch (e: Exception) {
                        result.error("generic", e.message ?: e.toString(), null)
                    }
                }
                "stopAdvertising" -> {
                    bleAdvertiser
                    bleAdvertiser?.stop()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun bleAdvertiser(): AeroBleAdvertiser =
        bleAdvertiser ?: AeroBleAdvertiser(applicationContext).also { bleAdvertiser = it }

    /** Whether this device can host, and what is missing if not. */
    private fun capability(): Map<String, Any> {
        val required = requiredPermission()
        val permissionsOk = required == null ||
            ContextCompat.checkSelfPermission(this, required) == PackageManager.PERMISSION_GRANTED

        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val supported = wifi != null && isApiLevelSufficient() && permissionsOk
        val reason = when {
            wifi == null -> "This device has no Wi-Fi."
            !isApiLevelSufficient() ->
                "A hotspot needs Android 8.0 or newer (API 26)."
            !permissionsOk ->
                "Aero does not have the $required permission yet."
            else -> ""
        }
        return mapOf(
            "supported" to supported,
            "reason" to reason,
            "permission" to (required ?: ""),
        )
    }

    /**
     * Request the OS create a local-only hotspot.
     *
     * [WifiManager.startLocalOnlyHotspot] is callback-based and asynchronous, so
     * the [MethodChannel.Result] is intentionally completed later, from the
     * callback, rather than at the end of this method.
     */
    private fun startHotspot(result: MethodChannel.Result) {
        if (reservation != null) {
            // Idempotent: hand back the running AP rather than failing. The Dart
            // side coalesces concurrent calls, but a rebuild can still land here.
            result.success(sessionJson(reservation!!))
            return
        }
        if (!isApiLevelSufficient()) {
            result.error("generic", "A hotspot needs Android 8.0 (API 26) or newer.", null)
            return
        }
        val required = requiredPermission()
        if (required != null && !hasPermission(required)) {
            // Prompt rather than fail: the user may simply never have been asked.
            // The start is re-run automatically once the dialog is answered, so
            // a first-time user does not have to tap twice.
            requestPermissionInternal(required) { granted ->
                if (granted) {
                    startHotspot(result)
                } else {
                    result.error(
                        "permission_denied",
                        "Aero needs the $required permission to create a hotspot.",
                        null,
                    )
                }
            }
            return
        }

        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        if (wifi == null) {
            result.error("generic", "This device has no Wi-Fi.", null)
            return
        }

        // A single completion guard: the callback can fire more than once on
        // some ROMs, and completing a MethodChannel.Result twice throws.
        var completed = false

        try {
            wifi.startLocalOnlyHotspot(
                object : WifiManager.LocalOnlyHotspotCallback() {
                    override fun onStarted(res: WifiManager.LocalOnlyHotspotReservation) {
                        if (completed) {
                            // A stray second callback: release it rather than
                            // leak a second reservation.
                            runCatching { res.close() }
                            return
                        }
                        completed = true
                        reservation = res
                        result.success(sessionJson(res))
                    }

                    override fun onStopped() {
                        reservation = null
                        if (!completed) {
                            completed = true
                            result.error("generic", "The hotspot stopped before it started.", null)
                        }
                    }

                    override fun onFailed(reason: Int) {
                        reservation = null
                        if (completed) return
                        completed = true
                        val (code, message) = when (reason) {
                            ERROR_NO_CHANNEL ->
                                "no_channel" to "No Wi-Fi channel is free right now."
                            ERROR_GENERIC ->
                                "generic" to "The system could not start the hotspot."
                            ERROR_INCOMPATIBLE_MODE ->
                                "incompatible_mode" to
                                    "Wi-Fi is in a mode that blocks a hotspot."
                            ERROR_TETHERING_DISALLOWED ->
                                "tethering_disallowed" to
                                    "Tethering is disabled on this device."
                            else ->
                                "generic" to "Hotspot start failed (reason $reason)."
                        }
                        result.error(code, message, reason)
                    }
                },
                mainHandler,
            )
        } catch (e: SecurityException) {
            // Raised instead of onFailed when the permission check races.
            if (!completed) {
                completed = true
                result.error("permission_denied", e.message ?: "Permission denied.", null)
            }
        } catch (e: IllegalStateException) {
            if (!completed) {
                completed = true
                result.error("incompatible_mode", e.message ?: "Wi-Fi is busy.", null)
            }
        } catch (e: Exception) {
            if (!completed) {
                completed = true
                result.error("generic", e.message ?: e.toString(), null)
            }
        }
    }

    /** Release the AP. Safe to call when none is running. */
    private fun stopHotspot() {
        val res = reservation
        reservation = null
        if (res == null) return
        try {
            res.close()
        } catch (e: Exception) {
            Log.w(TAG, "closing the hotspot reservation failed", e)
        }
    }

    // -------------------------------------------------------------------------
    // Runtime permission plumbing
    // -------------------------------------------------------------------------

    private fun hasPermission(permission: String): Boolean =
        ContextCompat.checkSelfPermission(this, permission) ==
            PackageManager.PERMISSION_GRANTED

    /**
     * Prompt for the hotspot permission, invoking [onResult] with the outcome.
     *
     * Only one request is in flight at a time: a second caller while the OS
     * dialog is up is queued behind the first rather than stacking dialogs, which
     * Android would refuse to show anyway.
     */
    private fun requestPermissionInternal(permission: String, onResult: (Boolean) -> Unit) {
        val existing = permissionCallback
        if (existing != null) {
            // A prompt is already up. Chain, so the second caller still gets an
            // answer instead of hanging forever.
            permissionCallback = { granted ->
                existing(granted)
                onResult(granted)
            }
            return
        }
        permissionCallback = onResult
        ActivityCompat.requestPermissions(this, arrayOf(permission), permissionRequestCode)
    }

    /** `requestPermission` is exposed so Dart can preflight before starting. */
    private fun requestHotspotPermission(result: MethodChannel.Result) {
        val required = requiredPermission()
        if (required == null || hasPermission(required)) {
            result.success(true)
            return
        }
        requestPermissionInternal(required) { granted -> result.success(granted) }
    }

    /**
     * Request the Android 12+ Bluetooth runtime permissions.
     *
     * Before API 31 advertising needed no runtime grant, so this succeeds
     * immediately there - which is correct, not a stub.
     */
    private fun requestBlePermission(result: MethodChannel.Result) {
        val required = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
        } else {
            emptyList()
        }
        val missing = required.filterNot { hasPermission(it) }
        if (missing.isEmpty()) {
            result.success(true)
            return
        }

        blePermissionCallback = { granted -> result.success(granted) }
        ActivityCompat.requestPermissions(this, missing.toTypedArray(), blePermissionRequestCode)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            permissionRequestCode -> {
                val callback = permissionCallback ?: return
                permissionCallback = null
                val granted = grantResults.isNotEmpty() &&
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
                callback(granted)
            }
            blePermissionRequestCode -> {
                val callback = blePermissionCallback ?: return
                blePermissionCallback = null
                // All-or-nothing: advertising without CONNECT cannot read back
                // its own state, so a partial grant is not good enough.
                val granted = grantResults.isNotEmpty() &&
                    grantResults.all { it == PackageManager.PERMISSION_GRANTED }
                callback(granted)
            }
            else -> return
        }
    }

    /**
     * The permission this OS version needs to host a hotspot.
     *
     * `NEARBY_WIFI_DEVICES` from API 33 (Android 13); before that,
     * `ACCESS_FINE_LOCATION` was the gate for local-only hotspot. Returns null
     * when this device predates the requirement entirely.
     */
    private fun requiredPermission(): String? = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU ->
            Manifest.permission.NEARBY_WIFI_DEVICES
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ->
            Manifest.permission.ACCESS_FINE_LOCATION
        else -> null
    }

    private fun isApiLevelSufficient() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O

    /**
     * Normalize the reservation into the small shape Dart expects.
     *
     * The SSID on a `LocalOnlyHotspot` is system-generated and stable; the
     * pre-shared key is what the other device types. There is no public API for
     * the phone's own address on the AP, so it is left empty here and the Mac
     * discovers it through mDNS or its default gateway instead of guessing.
     */
    private fun sessionJson(res: WifiManager.LocalOnlyHotspotReservation): Map<String, Any> {
        // `softApConfiguration` is API 30+; below that the reservation exposes a
        // legacy `wifiConfiguration`. Both carry the same two fields, and the
        // deprecated `.ssid` accessor on the newer type is avoided by branching
        // on SDK level rather than reading the wrong property.
        val ssid: String
        val psk: String
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val config = res.softApConfiguration
            // `getWifiSsid()` exists from API 33; `getSsid()` (deprecated there)
            // is the only option on 30-32. Both yield the broadcast name.
            ssid = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                config.getWifiSsid()?.toString() ?: ""
            } else {
                @Suppress("DEPRECATION")
                config.getSsid() ?: ""
            }
            psk = config.getPassphrase() ?: ""
        } else {
            @Suppress("DEPRECATION")
            run {
                val config = res.wifiConfiguration
                ssid = config?.SSID ?: ""
                psk = config?.preSharedKey ?: ""
            }
        }
        val security = if (psk.isEmpty()) "open" else "wpa2"
        return mapOf(
            "ssid" to ssid,
            "psk" to psk,
            "gatewayIp" to "",
            "security" to security,
            // The Mac must be told these and join by hand; the phone cannot make
            // it join. Signals the Dart side to drive the assisted-join flow.
            "requiresUserJoin" to true,
        )
    }

    override fun onDestroy() {
        // Backstop: if Dart never called stopHotspot, do not leave a network the
        // user cannot easily remove.
        stopHotspot()
        // Same for BLE: a lingering advertisement keeps the radio busy and makes
        // the phone visible to any scanner long after the app is gone.
        bleAdvertiser?.stop()
        bleAdvertiser = null
        channel?.setMethodCallHandler(null)
        channel = null
        bleChannel?.setMethodCallHandler(null)
        bleChannel = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AeroDirect"
        private const val CHANNEL = "aero/direct"
        private const val BLE_CHANNEL = "aero/ble"
    }
}
