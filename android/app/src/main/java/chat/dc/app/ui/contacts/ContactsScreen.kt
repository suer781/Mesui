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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ble.BleMesh
import chat.dc.app.core.SignalCore
import chat.dc.app.ui.components.EmptyState
import chat.dc.app.ui.components.InitialsAvatar
import chat.dc.core.Contact

/**
 * 联系人主 tab（阶段 5 接真数据）：功能入口卡片 + 真实联系人列表。
 * 数据 = contactStore.listContacts；在线点 = BleMesh.peers（蓝牙链路在位）；
 * 点击进聊天。长按删除先不做（误触代价高，删除入口放在后续设置）。
 */
@Composable
fun ContactsScreen(onOpenNearby: () -> Unit, onOpenAddFriend: () -> Unit, onOpenChat: (String) -> Unit) {
    val context = LocalContext.current
    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    val peers by BleMesh.peers.collectAsState()
    val pairing by BleMesh.pairing.collectAsState()

    // 列表读取挪 IO（P2，与聊天/消息页同纪律）：listContacts 走 SQLCipher，不进主线程
    LaunchedEffect(Unit) {
        contacts = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            runCatching { SignalCore.contactStore(context).listContacts() }.getOrDefault(emptyList())
        }
    }
    // 配对完成（有新联系人）后刷新列表
    LaunchedEffect(pairing) {
        contacts = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            runCatching { SignalCore.contactStore(context).listContacts() }.getOrDefault(emptyList())
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Text(
            stringResource(R.string.tab_contacts),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 14.dp),
        )
        LazyColumn {
            // 功能入口（列表顶部的图标行）
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
            if (contacts.isEmpty()) {
                item {
                    EmptyState(
                        icon = Icons.Filled.People,
                        title = stringResource(R.string.empty_contacts_title),
                        hint = stringResource(R.string.empty_contacts_hint),
                        actionText = stringResource(R.string.empty_action_add_friend),
                        onAction = onOpenAddFriend,
                    )
                }
            } else {
                items(contacts.size) { i ->
                    val c = contacts[i]
                    val identityHex = remember(c.identity) {
                        c.identity.joinToString("") { "%02x".format(it) }
                    }
                    val online = peers[identityHex] == chat.dc.app.ble.PeerState.ONLINE
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenChat(c.name) }
                            .padding(horizontal = 20.dp, vertical = 12.dp)
                            .testTag("contact_row_${c.name}"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        InitialsAvatar(c.name.take(1), size = 44, corner = 14)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 12.dp),
                        ) {
                            Text(c.name, style = MaterialTheme.typography.bodyLarge)
                            if (c.note.isNotBlank()) {
                                Text(
                                    c.note,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        if (c.verified) {
                            Icon(
                                Icons.Filled.Verified,
                                contentDescription = stringResource(R.string.contacts_verified_desc),
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                        // 在线指示：蓝牙链路在位（iroh 为按需建连，不在此断言）
                        Box(
                            modifier = Modifier
                                .padding(start = 8.dp)
                                .size(10.dp)
                                .background(
                                    if (online) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                                    CircleShape,
                                ),
                        )
                    }
                }
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
    // 入口卡片化（色阶容器 + 20dp 大圆角，无边框无阴影）
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
