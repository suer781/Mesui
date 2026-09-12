package chat.dc.app.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ble.BleMesh
import chat.dc.app.core.SignalCore
import chat.dc.app.ui.components.EmptyState
import chat.dc.core.ChatMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 聊天会话页（阶段 5 接真数据）：
 * - 历史：contactStore.messages 落库记录（SQLCipher，重启不丢）
 * - 接收：BleMesh.incoming 统一入站流（BLE 近场 + iroh 远程均汇入）实时追加
 * - 发送：BleMesh.sendText（BLE 链路优先，无链路走 iroh 跨网络）；失败给提示
 */
@Composable
fun ChatScreen(contactId: String, onBack: () -> Unit, onAddFriend: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var messages by remember { mutableStateOf<List<ChatMessage>>(emptyList()) }
    var draft by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // reload 统一挪 IO（P2）：入站消息高频触发的 reload 旧码在主线程跑
    // SQLCipher 查询（解密库读 500 行），弱机上掉帧明显
    fun reload() {
        scope.launch {
            val list = withContext(Dispatchers.IO) {
                runCatching { SignalCore.contactStore(context).messages(contactId, 500) }
                    .getOrDefault(emptyList())
            }
            messages = list
        }
    }

    LaunchedEffect(contactId) { reload() }
    // 入站消息（任意通道）到达 → 刷新列表
    LaunchedEffect(contactId) {
        BleMesh.incoming.collect {
            if (it.peerName == contactId) reload()
        }
    }
    // 列表变化后自动跟随到底：仅「首次加载」或「用户已贴近底部」时滚动，
    // 上翻浏览历史时不打扰（缺陷 A：此前无脑滚到底会打断历史浏览）
    var initialScrollDone by remember(contactId) { mutableStateOf(false) }
    LaunchedEffect(messages.size) {
        if (messages.isEmpty()) return@LaunchedEffect
        val layout = listState.layoutInfo
        val lastIndex = messages.size - 1
        val lastVisible = layout.visibleItemsInfo.lastOrNull()?.index ?: -1
        val nearBottom = lastVisible >= lastIndex - 1
        if (!initialScrollDone || nearBottom) {
            listState.scrollToItem(lastIndex)
            initialScrollDone = true
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        modifier = Modifier.fillMaxSize(),
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().imePadding().padding(padding)) {
            // 顶栏：会话名 = 联系人地址名（ProtocolAddress + chat_log 主键）
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onBack, modifier = Modifier.testTag("chat_back")) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                }
                Text(
                    contactId,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            if (messages.isEmpty()) {
                EmptyState(
                    icon = Icons.Filled.ChatBubbleOutline,
                    title = stringResource(R.string.empty_chat_title),
                    hint = stringResource(R.string.empty_chat_hint),
                    actionText = stringResource(R.string.empty_action_add_friend),
                    onAction = onAddFriend,
                    modifier = Modifier.weight(1f),
                )
            } else {
                // 气泡列表
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(messages.size) { i ->
                        val m = messages[i]
                        val time = remember(m.tsMs) {
                            SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.tsMs))
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .animateItem(),
                            horizontalArrangement = if (m.outgoing) Arrangement.End else Arrangement.Start,
                        ) {
                            val screenWidth = LocalConfiguration.current.screenWidthDp
                            Surface(
                                color = if (m.outgoing) {
                                    MaterialTheme.colorScheme.primaryContainer
                                } else {
                                    MaterialTheme.colorScheme.surfaceVariant
                                },
                                shape = RoundedCornerShape(
                                    topStart = 18.dp,
                                    topEnd = 18.dp,
                                    bottomStart = if (m.outgoing) 18.dp else 4.dp,
                                    bottomEnd = if (m.outgoing) 4.dp else 18.dp,
                                ),
                                modifier = Modifier.widthIn(max = (screenWidth * 0.78f).dp),
                            ) {
                                Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                                    Text(m.text, style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        time,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.align(Alignment.End),
                                    )
                                }
                            }
                        }
                    }
                }
            }
            // 输入栏：发送走真链路（BLE/iroh），失败提示对方不在线
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("chat_input"),
                    placeholder = { Text(stringResource(R.string.chat_input_hint)) },
                    shape = RoundedCornerShape(24.dp),
                    maxLines = 4,
                    colors = OutlinedTextFieldDefaults.colors(
                        // 极简 chrome——未聚焦无边框，用容器色分层
                        unfocusedBorderColor = androidx.compose.ui.graphics.Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                )
                IconButton(
                    onClick = {
                        val text = draft.trim()
                        if (text.isNotBlank() && !sending) {
                            sending = true
                            scope.launch {
                                // sendText 阻塞等 iroh 确认：必须离开主线程
                                val ok = withContext(Dispatchers.IO) { BleMesh.sendText(contactId, text) }
                                sending = false
                                if (ok) {
                                    draft = ""
                                    reload()
                                } else {
                                    snackbar.showSnackbar(context.getString(R.string.chat_send_offline))
                                }
                            }
                        }
                    },
                    modifier = Modifier
                        .padding(start = 8.dp)
                        .testTag("chat_send"),
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}
