package chat.dc.app.nearby

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.UUID

/**
 * 附近设备发现（BLE 扫描/广播 + 经典蓝牙 bonded 列表）。
 *
 * 权限模型：
 * - API 31+：BLUETOOTH_SCAN（neverForLocation）/ BLUETOOTH_CONNECT / BLUETOOTH_ADVERTISE
 * - API 26-30：ACCESS_FINE_LOCATION + 旧 BLUETOOTH 权限（manifest 已按 maxSdkVersion 配好）
 *
 * 隐私边界：只扫描声明了本应用服务 UUID 的对等节点；全量设备发现仅供
 * 调试面板使用，默认关闭。
 */
class NearbyDiscovery(private val context: Context) {

    companion object {
        /** DC 聊天 BLE 服务 UUID：只有广播它的设备才会被当作对等节点展示。 */
        val SERVICE_UUID: UUID = UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e5f")
    }

    enum class Status { IDLE, NO_PERMISSION, BLUETOOTH_OFF, SCANNING, SCANNED, SCAN_FAILED }

    data class NearbyPeer(
        val address: String,
        val name: String?,
        val rssi: Int,
        val serviceMatch: Boolean,
    )

    data class NearbyState(
        val status: Status = Status.IDLE,
        val peers: Map<String, NearbyPeer> = emptyMap(),
        val advertising: Boolean = false,
    )

    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val adapter: BluetoothAdapter? get() = bluetoothManager?.adapter

    private val _state = MutableStateFlow(NearbyState())
    val state: StateFlow<NearbyState> = _state.asStateFlow()

    fun requiredPermissions(): Array<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // ADVERTISE 必须在授权流程内申请，否则「允许被发现」静默失效
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    fun hasPermissions(): Boolean = requiredPermissions().all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    fun bluetoothEnabled(): Boolean = adapter?.isEnabled == true

    /** 进入页面时同步一次状态（不启动任何动作）：
     *  初始 IDLE 态下用户看不到任何权限引导。 */
    fun refreshState() {
        _state.update {
            when {
                !hasPermissions() -> it.copy(status = Status.NO_PERMISSION)
                !bluetoothEnabled() -> it.copy(status = Status.BLUETOOTH_OFF)
                else -> it.copy(status = Status.IDLE)
            }
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val address = result.device.address
            val matched = result.scanRecord
                ?.serviceUuids
                ?.any { it.uuid == SERVICE_UUID } == true
            _state.update { s ->
                val peer = NearbyPeer(
                    address = address,
                    name = result.scanRecord?.deviceName,
                    rssi = result.rssi,
                    serviceMatch = matched,
                )
                s.copy(status = Status.SCANNING, peers = s.peers + (address to peer))
            }
        }

        override fun onScanFailed(errorCode: Int) {
            // 失败必须与「正常停止」可区分，UI 才有反馈
            _state.update { it.copy(status = Status.SCAN_FAILED) }
        }
    }

    /** 开始 BLE 扫描；默认只收本服务 UUID 的广播包。 */
    fun startScan(filterToService: Boolean = true) {
        if (!hasPermissions()) {
            _state.update { it.copy(status = Status.NO_PERMISSION) }
            return
        }
        val a = adapter
        if (a == null || !a.isEnabled) {
            _state.update { it.copy(status = Status.BLUETOOTH_OFF) }
            return
        }
        val scanner = a.bluetoothLeScanner ?: run {
            // 蓝牙开着但无 LE 扫描器（老硬件）：与正常停止区分开
            _state.update { it.copy(status = Status.SCAN_FAILED) }
            return
        }
        val filters = if (filterToService) {
            listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build())
        } else {
            emptyList()
        }
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        _state.update { it.copy(status = Status.SCANNING, peers = emptyMap()) }
        try {
            scanner.startScan(filters, settings, scanCallback)
        } catch (_: SecurityException) {
            // 权限检查与调用之间存在被撤销的竞态（Lint MissingPermission）
            _state.update { it.copy(status = Status.NO_PERMISSION) }
        }
    }

    fun stopScan() {
        if (hasPermissions()) {
            // 个别机型未开始扫描时 stopScan 也会抛远程异常，不能让它炸掉界面
            try {
                adapter?.bluetoothLeScanner?.stopScan(scanCallback)
            } catch (_: SecurityException) {
            } catch (_: IllegalStateException) {
            }
        }
        _state.update { it.copy(status = Status.SCANNED) }
    }

    /**
     * 经典蓝牙：已配对设备（RFCOMM 直连的历史依据；真正加好友走 NFC/QR，
     * 此列表用于展示与回连已知联系人设备）。
     */
    fun bondedPeers(): List<NearbyPeer> {
        if (!hasPermissions()) return emptyList()
        val a = adapter ?: return emptyList()
        return try {
            a.bondedDevices.orEmpty().map {
                NearbyPeer(address = it.address, name = it.name, rssi = Int.MIN_VALUE, serviceMatch = false)
            }
        } catch (_: SecurityException) {
            emptyList()
        }
    }

    /** 开始对外广播本应用服务 UUID：让附近的对等节点能发现我们。 */
    fun startAdvertising() {
        if (!hasPermissions()) {
            _state.update { it.copy(status = Status.NO_PERMISSION) }
            return
        }
        val advertiser = adapter?.bluetoothLeAdvertiser ?: return
        val settings = android.bluetooth.le.AdvertiseSettings.Builder()
            .setAdvertiseMode(android.bluetooth.le.AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .build()
        val data = android.bluetooth.le.AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            // 安全约束：不广播设备名——那会把手机蓝牙名（常含真名）
            // 透露给任何扫描者；对端靠服务 UUID 过滤即可
            .setIncludeDeviceName(false)
            .build()
        try {
            advertiser.startAdvertising(settings, data, advertiseCallback)
        } catch (_: SecurityException) {
            _state.update { it.copy(advertising = false) }
        }
    }

    fun stopAdvertising() {
        if (!hasPermissions()) return
        try {
            adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        } catch (_: SecurityException) {
        }
        _state.update { it.copy(advertising = false) }
    }

    private val advertiseCallback = object : android.bluetooth.le.AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: android.bluetooth.le.AdvertiseSettings?) {
            _state.update { it.copy(advertising = true) }
        }

        override fun onStartFailure(errorCode: Int) {
            _state.update { it.copy(advertising = false) }
        }
    }
}
