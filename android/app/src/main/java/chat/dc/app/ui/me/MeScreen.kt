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
import androidx.compose.material3.Badge
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ui.components.InitialsAvatar

/**
 * 「我的」主 tab：个人资料卡 + 设置分区列表。
 * 各行均为入口占位；设置中心十二类待接入。
 */
@Composable
fun MeScreen(onOpenAddFriend: () -> Unit) {
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
            InitialsAvatar("我", size = 64, corner = 20)
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 14.dp),
            ) {
                Text(stringResource(R.string.me_name), style = MaterialTheme.typography.titleLarge)
                Text(
                    stringResource(R.string.me_status_placeholder),
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
            SettingRow(Icons.Filled.Shield, stringResource(R.string.me_row_security), badge = stringResource(R.string.me_badge_unwired))
            SettingRow(Icons.Filled.Lan, stringResource(R.string.me_row_node), badge = stringResource(R.string.me_node_running), live = true)
            SettingRow(Icons.Filled.Storage, stringResource(R.string.me_row_storage), badge = stringResource(R.string.me_badge_unwired))
        }
        SectionCard {
            SettingRow(Icons.Filled.Info, stringResource(R.string.me_row_about), badge = stringResource(R.string.me_badge_unwired))
        }
    }
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
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { /* 待接入设置子页 */ }
            .padding(horizontal = 16.dp, vertical = 14.dp),
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
