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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import chat.dc.app.ui.components.EmptyState

/** 消息主 tab：搜索框 + 引导空态（核心数据接入前不放演示会话）。 */
@Composable
fun MessagesScreen(onOpenChat: (String) -> Unit, onOpenAddFriend: () -> Unit = {}) {
    var query by remember { mutableStateOf("") }
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
            // P8 收纳：新会话入口 = 添加好友（联系人来自这里）
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
        // 核心数据接入前没有会话可列出：展示引导空态，而不是演示数据
        EmptyState(
            icon = Icons.Filled.ChatBubbleOutline,
            title = stringResource(R.string.empty_messages_title),
            hint = stringResource(R.string.empty_messages_hint),
            actionText = stringResource(R.string.empty_action_add_friend),
            onAction = onOpenAddFriend,
            modifier = Modifier.weight(1f),
        )
    }
}
