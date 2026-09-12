package chat.dc.app.ui.messages

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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import chat.dc.app.R
import chat.dc.app.ble.BleMesh
import chat.dc.app.core.SignalCore
import chat.dc.app.ui.components.EmptyState
import chat.dc.app.ui.components.InitialsAvatar
import chat.dc.core.ChatMessage
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 消息主 tab（阶段 5 接真数据）：搜索框 + 会话列表。
 * 数据 = contactStore.lastMessages（每联系人最新一条，时间降序）+ 联系人名；
 * 入站消息（BLE/iroh）实时刷新；回到本页（ON_RESUME）也刷新（发送后返回可见）。
 */
@Composable
fun MessagesScreen(onOpenChat: (String) -> Unit, onOpenAddFriend: () -> Unit = {}) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var query by remember { mutableStateOf("") }
    var chats by remember { mutableStateOf<List<ChatMessage>>(emptyList()) }

    fun reload() {
        chats = runCatching { SignalCore.contactStore(context).lastMessages() }.getOrDefault(emptyList())
    }

    LaunchedEffect(Unit) { reload() }
    // 收到任意入站消息即刷新（列表 = 最新消息排序）
    LaunchedEffect(Unit) {
        BleMesh.incoming.collect { reload() }
    }
    // 从聊天页返回时刷新（发出去的消息也要出现在列表）
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) reload()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val shown = remember(query, chats) {
        if (query.isBlank()) chats
        else chats.filter { it.peer.contains(query, ignoreCase = true) || it.text.contains(query, ignoreCase = true) }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.tab_messages),
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.weight(1f),
            )
            // 收纳：新会话入口 = 添加好友（联系人来自这里）
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clickable(onClick = onOpenAddFriend)
                    .background(
                        MaterialTheme.colorScheme.primary,
                        CircleShape,
                    )
                    .testTag("new_chat"),
                contentAlignment = Alignment.Center,
            ) {
                androidx.compose.material3.Icon(
                    Icons.Filled.Add,
                    contentDescription = stringResource(R.string.new_chat_desc),
                    tint = MaterialTheme.colorScheme.onPrimary,
                )
            }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = { Text(stringResource(R.string.search_hint)) },
            leadingIcon = {
                androidx.compose.material3.Icon(
                    Icons.Filled.Search,
                    contentDescription = stringResource(R.string.search_desc),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            shape = RoundedCornerShape(24.dp),
            maxLines = 1,
            colors = OutlinedTextFieldDefaults.colors(
                unfocusedBorderColor = androidx.compose.ui.graphics.Color.Transparent,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .testTag("search"),
        )
        if (shown.isEmpty()) {
            EmptyState(
                icon = Icons.Filled.ChatBubbleOutline,
                title = stringResource(R.string.empty_messages_title),
                hint = stringResource(R.string.empty_messages_hint),
                actionText = stringResource(R.string.empty_action_add_friend),
                onAction = onOpenAddFriend,
                modifier = Modifier.weight(1f),
            )
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(shown.size) { i ->
                    val chat = shown[i]
                    val time = remember(chat.tsMs) {
                        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(chat.tsMs))
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenChat(chat.peer) }
                            .padding(horizontal = 20.dp, vertical = 12.dp)
                            .testTag("chat_row_${chat.peer}"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        InitialsAvatar(chat.peer.take(1), size = 44, corner = 14)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 12.dp),
                        ) {
                            Text(chat.peer, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                chat.text,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                            )
                        }
                        Text(
                            time,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (i < shown.size - 1) {
                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 20.dp),
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                        )
                    }
                }
            }
        }
    }
}
