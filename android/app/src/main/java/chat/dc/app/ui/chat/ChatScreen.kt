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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ui.components.EmptyState
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 单条气泡消息（仅本页内存展示，不落盘；真实收发待核心接入后走信封+队列）。 */
private data class Message(val text: String, val sent: Boolean, val time: String)

/**
 * 聊天会话页气泡：接收=左侧 surfaceVariant，发送=右侧 primaryContainer。
 * 核心数据接入前无会话/消息可显示，展示引导空态；输入栏保留，发送仅写入本页内存。
 */
@Composable
fun ChatScreen(onBack: () -> Unit, onAddFriend: () -> Unit) {
    val scope = rememberCoroutineScope()
    val messages = remember { mutableStateOf<List<Message>>(emptyList()) }
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    Column(modifier = Modifier.fillMaxSize().imePadding()) {
        // 顶栏：会话名待真实联系人数据接入后显示，先以占位标题呈现
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
                stringResource(R.string.chat_title_placeholder),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (messages.value.isEmpty()) {
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
                items(messages.value.size) { i ->
                    val m = messages.value[i]
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .animateItem(),
                        horizontalArrangement = if (m.sent) Arrangement.End else Arrangement.Start,
                    ) {
                        val screenWidth = LocalConfiguration.current.screenWidthDp
                        Surface(
                            color = if (m.sent) {
                                MaterialTheme.colorScheme.primaryContainer
                            } else {
                                MaterialTheme.colorScheme.surfaceVariant
                            },
                            shape = RoundedCornerShape(
                                topStart = 18.dp,
                                topEnd = 18.dp,
                                bottomStart = if (m.sent) 18.dp else 4.dp,
                                bottomEnd = if (m.sent) 4.dp else 18.dp,
                            ),
                            modifier = Modifier.widthIn(max = (screenWidth * 0.78f).dp),
                        ) {
                            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                                Text(m.text, style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    m.time,
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
        // 输入栏
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
                    if (draft.isNotBlank()) {
                        val time = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date())
                        messages.value = messages.value + Message(draft.trim(), sent = true, time = time)
                        draft = ""
                        scope.launch { listState.scrollToItem(messages.value.size - 1) }
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
