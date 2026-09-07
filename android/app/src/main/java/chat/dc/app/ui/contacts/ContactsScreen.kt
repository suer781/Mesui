package chat.dc.app.ui.contacts

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ui.components.EmptyState

/** 联系人主 tab：功能入口卡片（图标+底色）+ 联系人列表空态（核心数据接入前不放演示联系人）。 */
@Composable
fun ContactsScreen(onOpenNearby: () -> Unit, onOpenAddFriend: () -> Unit, onOpenChat: (String) -> Unit) {
    Column(modifier = Modifier.fillMaxSize()) {
        Text(
            stringResource(R.string.tab_contacts),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 14.dp),
        )
        LazyColumn {
            // 功能入口（微信排版结构：列表顶部的图标行）
            item {
                EntryRow(
                    icon = { Icon(Icons.Filled.PersonAdd, null, tint = Color.White) },
                    container = MaterialTheme.colorScheme.primary,
                    title = stringResource(R.string.add_friend_title),
                    subtitle = stringResource(R.string.contacts_entry_qr),
                    tag = "open_add_friend",
                    onClick = onOpenAddFriend,
                )
            }
            item {
                EntryRow(
                    icon = { Icon(Icons.Filled.Radar, null, tint = Color.White) },
                    container = MaterialTheme.colorScheme.tertiary,
                    title = stringResource(R.string.nearby_title),
                    subtitle = stringResource(R.string.contacts_entry_nearby),
                    tag = "open_nearby",
                    onClick = onOpenNearby,
                )
            }
            // 核心数据接入前没有联系人可列出：展示引导空态，而不是演示数据
            item {
                EmptyState(
                    icon = Icons.Filled.People,
                    title = stringResource(R.string.empty_contacts_title),
                    hint = stringResource(R.string.empty_contacts_hint),
                    actionText = stringResource(R.string.empty_action_add_friend),
                    onAction = onOpenAddFriend,
                )
            }
        }
    }
}

@Composable
private fun EntryRow(
    icon: @Composable () -> Unit,
    container: Color,
    title: String,
    subtitle: String,
    tag: String,
    onClick: () -> Unit,
) {
    // P3/P8：入口卡片化（色阶容器 + 20dp 大圆角，无边框无阴影）
    androidx.compose.material3.Card(
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
        shape = MaterialTheme.shapes.large,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp)
            .clickable(onClick = onClick)
            .testTag(tag),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(container, RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center,
            ) {
                icon()
            }
            Column(modifier = Modifier.padding(horizontal = 12.dp)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

