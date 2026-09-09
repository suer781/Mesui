package chat.dc.app.ui.me

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.core.IrohNodeManager
import chat.dc.app.core.SignalCore
import chat.dc.app.ui.components.InitialsAvatar
import chat.dc.core.CoreInfo
import java.io.File

/**
 * 「我的」主 tab：个人资料卡 + 设置分区（全部接真实数据，无占位行）。
 * - 资料：设备地址名（ProtocolAddress/SAS 本地标识）+ 身份指纹前 16 位
 * - 节点服务：iroh 端点真实状态 + 节点 ID + 自建中继配置（保存即重启生效）
 * - 数据与存储：SQLCipher 库/密钥/节点密钥文件真实大小
 * - 隐私与安全：TOFU 策略说明（协议事实，非开关）
 * - 关于：CoreInfo 的版本与许可证
 */
@Composable
fun MeScreen(onOpenAddFriend: () -> Unit) {
    val context = LocalContext.current
    val session = remember { runCatching { SignalCore.session(context) }.getOrNull() }
    val deviceName = remember { SignalCore.deviceName(context) }
    val fingerprint = remember {
        session?.identityKey()?.joinToString("") { "%02x".format(it) }.orEmpty()
    }
    val irohSnap by IrohNodeManager.state.collectAsState()

    var showNode by remember { mutableStateOf(false) }
    var showStorage by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var showSecurity by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // 个人资料卡（水生渐变：primaryContainer→tertiaryContainer 柔和底）
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .background(
                    androidx.compose.ui.graphics.Brush.linearGradient(
                        listOf(
                            MaterialTheme.colorScheme.primaryContainer,
                            MaterialTheme.colorScheme.tertiaryContainer,
                        ),
                    ),
                    androidx.compose.foundation.shape.RoundedCornerShape(24.dp),
                )
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            InitialsAvatar(deviceName.take(1).uppercase(), size = 64, corner = 20)
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 14.dp),
            ) {
                Text(deviceName, style = MaterialTheme.typography.titleLarge)
                Text(
                    stringResource(R.string.me_identity_fp, fingerprint.take(16)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape)
                    .clickable(onClick = onOpenAddFriend)
                    .testTag("me_qr"),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Filled.QrCode2,
                    contentDescription = stringResource(R.string.add_friend_qr_desc),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        SectionCard {
            SettingRow(
                Icons.Filled.Lan,
                stringResource(R.string.me_row_node),
                subtitle = irohSnap.nodeIdHex.take(16).ifEmpty { null },
                badge = stringResource(if (irohSnap.running) R.string.me_node_running else R.string.me_node_stopped),
                live = irohSnap.running,
                onClick = { showNode = true },
                tag = "me_node_row",
            )
            SettingRow(
                Icons.Filled.Shield,
                stringResource(R.string.me_row_security),
                subtitle = stringResource(R.string.me_security_subtitle),
                onClick = { showSecurity = true },
            )
            SettingRow(
                Icons.Filled.Storage,
                stringResource(R.string.me_row_storage),
                subtitle = storageSummary(context),
                onClick = { showStorage = true },
            )
        }
        SectionCard {
            SettingRow(
                Icons.Filled.Info,
                stringResource(R.string.me_row_about),
                onClick = { showAbout = true },
            )
        }
    }

    if (showNode) {
        NodePanelDialog(
            snap = irohSnap,
            onDismiss = { showNode = false },
        )
    }
    if (showStorage) {
        AlertDialog(
            onDismissRequest = { showStorage = false },
            title = { Text(stringResource(R.string.me_row_storage)) },
            text = {
                Column {
                    Text(stringResource(R.string.storage_db, fileSize(File(context.filesDir, "dc-signal.db"))))
                    Text(stringResource(R.string.storage_dbkey, fileSize(File(context.filesDir, "dc.dbkey"))))
                    Text(stringResource(R.string.storage_nodekey, fileSize(File(context.filesDir, "dc.nodekey"))))
                }
            },
            confirmButton = {
                TextButton(onClick = { showStorage = false }) { Text(stringResource(R.string.action_close)) }
            },
        )
    }
    if (showSecurity) {
        AlertDialog(
            onDismissRequest = { showSecurity = false },
            title = { Text(stringResource(R.string.me_row_security)) },
            text = { Text(stringResource(R.string.security_tofu_body)) },
            confirmButton = {
                TextButton(onClick = { showSecurity = false }) { Text(stringResource(R.string.action_close)) }
            },
        )
    }
    if (showAbout) {
        val info = remember { runCatching { CoreInfo() }.getOrNull() }
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text(stringResource(R.string.me_row_about)) },
            text = {
                Column {
                    val version = runCatching { info?.version().orEmpty() }.getOrDefault("")
                    val license = runCatching { info?.license().orEmpty() }.getOrDefault("")
                    Text(stringResource(R.string.about_version, version))
                    Text(stringResource(R.string.about_license, license))
                }
            },
            confirmButton = {
                TextButton(onClick = { showAbout = false }) { Text(stringResource(R.string.action_close)) }
            },
        )
    }
}

/** 节点服务面板：真实端点状态 + 自建中继配置（保存重启生效）。 */
@Composable
private fun NodePanelDialog(snap: chat.dc.app.core.IrohSnap, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var relay by remember { mutableStateOf(IrohNodeManager.relayUrl(context)) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.me_row_node)) },
        text = {
            Column {
                Text(
                    stringResource(
                        if (snap.running) R.string.me_node_running else R.string.me_node_stopped,
                    ),
                    color = if (snap.running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (snap.nodeIdHex.isNotEmpty()) {
                    Text(
                        stringResource(R.string.node_my_id, snap.nodeIdHex),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    stringResource(R.string.node_relay_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = relay,
                    onValueChange = { relay = it },
                    placeholder = { Text(stringResource(R.string.node_relay_placeholder)) },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("node_relay_input"),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    IrohNodeManager.setRelayUrlAndRestart(context, relay)
                    onDismiss()
                },
                modifier = Modifier.testTag("node_relay_save"),
            ) { Text(stringResource(R.string.node_save_restart)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_close)) }
        },
    )
}

@Composable
private fun SectionCard(content: @Composable () -> Unit) {
    androidx.compose.material3.Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        shape = MaterialTheme.shapes.large,
    ) {
        Column(modifier = Modifier.padding(vertical = 4.dp)) { content() }
    }
}

@Composable
private fun SettingRow(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    badge: String? = null,
    live: Boolean = false,
    onClick: () -> Unit = {},
    tag: String? = null,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .let { if (tag != null) it.testTag(tag) else it },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp),
        )
        Column(modifier = Modifier.weight(1f).padding(horizontal = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (badge != null) {
            Badge(
                containerColor = if (live) {
                    MaterialTheme.colorScheme.tertiary
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                contentColor = if (live) {
                    MaterialTheme.colorScheme.onTertiary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            ) { Text(badge) }
        }
        Icon(
            Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun fileSize(file: File): String {
    val len = runCatching { file.length() }.getOrDefault(0L)
    return if (len >= 1024) "${"%.1f".format(len / 1024.0)} KB" else "$len B"
}

@Composable
private fun storageSummary(context: android.content.Context): String =
    stringResource(
        R.string.me_storage_subtitle,
        fileSize(File(context.filesDir, "dc-signal.db")),
    )
