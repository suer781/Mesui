package chat.dc.app.nearby

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 附近设备发现的状态机运行时验证（Robolectric JVM，无真机）。
 * 覆盖：分版本权限映射 / 无权限拒绝 / 蓝牙关闭路径 / 未授权 bonded 不崩。
 */
@RunWith(RobolectricTestRunner::class)
class NearbyDiscoveryTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    @Config(sdk = [30])
    fun permissions_onApi30_requireFineLocation() {
        val d = NearbyDiscovery(context)
        assertTrue(
            d.requiredPermissions().contentEquals(arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION)),
        )
        assertFalse(d.hasPermissions())
    }

    @Test
    @Config(sdk = [31])
    fun permissions_onApi31_useBluetoothRuntimePermissions() {
        val d = NearbyDiscovery(context)
        assertEquals(
            setOf(
                android.Manifest.permission.BLUETOOTH_SCAN,
                android.Manifest.permission.BLUETOOTH_CONNECT,
                android.Manifest.permission.BLUETOOTH_ADVERTISE,
            ),
            d.requiredPermissions().toSet(),
        )
    }

    @Test
    @Config(sdk = [33])
    fun startScan_withoutPermissions_entersNoPermission() = runTest {
        val d = NearbyDiscovery(context)
        d.startScan()
        assertEquals(NearbyDiscovery.Status.NO_PERMISSION, d.state.first().status)
    }

    @Test
    @Config(sdk = [33])
    fun startScan_withPermissionsButBluetoothOff_entersBluetoothOff() = runTest {
        val d = NearbyDiscovery(context)
        shadowOf(context as android.app.Application).grantPermissions(
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_ADVERTISE,
        )
        d.startScan()
        // Robolectric 无真实蓝牙栈：adapter 关闭或不存在都必须落在 BLUETOOTH_OFF，
        // 且不得抛异常（真机上这是最常见路径之一）
        assertEquals(NearbyDiscovery.Status.BLUETOOTH_OFF, d.state.first().status)
    }

    @Test
    @Config(sdk = [33])
    fun bondedPeers_withoutPermissions_returnsEmptyWithoutCrash() {
        val d = NearbyDiscovery(context)
        assertTrue(d.bondedPeers().isEmpty())
    }

    @Test
    @Config(sdk = [33])
    fun stopScan_withoutScanStarted_isSafe() = runTest {
        val d = NearbyDiscovery(context)
        shadowOf(context as android.app.Application).grantPermissions(
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_CONNECT,
        )
        d.stopScan() // 未开始扫描就停止：不得抛异常（B 修复的回归验证）
        assertEquals(NearbyDiscovery.Status.SCANNED, d.state.first().status)
        assertEquals(Build.VERSION.SDK_INT, Build.VERSION_CODES.TIRAMISU)
    }
}
