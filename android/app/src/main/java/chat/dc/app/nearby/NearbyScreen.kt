package chat.dc.app.nearby

import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R

/**
 * 发现附近设备子页：权限引导 → BLE 扫描（只认本应用服务 UUID）+ 对外广播。
 * 整页为单一 LazyColumn（头部作 item、设备作 items）——不能在 verticalScroll
 * 里嵌 LazyColumn（无限高度约束会崩）。
 */
@Composable
fun NearbyScreen() {
    val context = LocalContext.current
    val discovery = remember { NearbyDiscovery(context) }
    val state by discovery.state.collectAsState()
    var filterToService by remember { mutableStateOf(true) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        if (grants.values.all { it }) {
            discovery.startScan(filterToService)
        }
    }

    val enableBtLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { discovery.refreshState() /* 蓝牙开启结果回填状态 */ }

    DisposableEffect(Unit) {
        discovery.refreshState()
        onDispose { discovery.stopScan(); discovery.stopAdvertising() }
    }

    LazyColumn(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
        item {
            Text(stringResource(R.string.nearby_title), style = MaterialTheme.typography.titleLarge)
        }
        when (state.status) {
            NearbyDiscovery.Status.NO_PERMISSION -> item {
                Text(stringResource(R.string.nearby_need_permission), modifier = Modifier.padding(vertical = 8.dp))
                Button(onClick = { permissionLauncher.launch(discovery.requiredPermissions()) }) {
                    Text(stringResource(R.string.nearby_grant))
                }
            }
            NearbyDiscovery.Status.BLUETOOTH_OFF -> item {
                Text(stringResource(R.string.nearby_bluetooth_off), modifier = Modifier.padding(vertical = 8.dp))
                Button(onClick = {
                    enableBtLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
                }) { Text(stringResource(R.string.nearby_enable_bluetooth)) }
                OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS)) }) {
                    Text(stringResource(R.string.nearby_open_settings))
                }
            }
            NearbyDiscovery.Status.SCAN_FAILED -> item {
                Text(
                    stringResource(R.string.nearby_scan_failed),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            }
            else -> Unit
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(onClick = {
                    if (state.status == NearbyDiscovery.Status.SCANNING) {
                        discovery.stopScan()
                    } else {
                        discovery.startScan(filterToService)
                    }
                }) {
                    Text(
                        when (state.status) {
                            NearbyDiscovery.Status.SCANNING -> stringResource(R.string.nearby_stop)
                            else -> stringResource(R.string.nearby_start)
                        },
                    )
                }
                Text(stringResource(R.string.nearby_only_ours))
                Switch(checked = filterToService, onCheckedChange = { filterToService = it })
            }
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.nearby_advertise))
                    Text(
                        stringResource(R.string.nearby_advertise_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = state.advertising,
                    onCheckedChange = { on ->
                        if (on) discovery.startAdvertising() else discovery.stopAdvertising()
                    },
                )
            }
        }
        item {
            Text(
                text = stringResource(R.string.nearby_found, state.peers.size),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(vertical = 8.dp),
            )
        }
        items(state.peers.values.toList(), key = { it.address }) { peer ->
            Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    chat.dc.app.ui.components.IconAvatar(
                        icon = Icons.Filled.Sensors,
                        size = 40,
                        corner = 12,
                    )
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 12.dp),
                    ) {
                        Text(
                            // 隐私：只显示单向派生的匿名别名，绝不显示蓝牙 MAC
                            // 或对方广播名——MAC 是可被追踪的硬件标识
                            stringResource(R.string.nearby_alias, peer.alias),
                            style = MaterialTheme.typography.titleSmall,
                        )
                        Text(
                            if (peer.serviceMatch) {
                                stringResource(R.string.nearby_dc_node)
                            } else {
                                stringResource(R.string.nearby_other_device)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        if (peer.rssi == Int.MIN_VALUE) {
                            stringResource(R.string.nearby_bonded)
                        } else {
                            stringResource(R.string.nearby_rssi, peer.rssi)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
