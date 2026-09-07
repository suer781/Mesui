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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Badge
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
import chat.dc.app.ui.DemoData
import chat.dc.app.ui.components.InitialsAvatar

/** 消息主 tab：搜索（真实过滤）+ 会话列表（头像/预览/时间/未读徽标）。 */
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
        val shown = DemoData.conversations.filter {
            query.isBlank() || it.name.contains(query, ignoreCase = true) ||
                it.preview.contains(query, ignoreCase = true)
        }
        LazyColumn {
            items(shown, key = { it.id }) { c ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .animateItem()
                        .clickable { onOpenChat(c.id) }
                        .padding(horizontal = 16.dp, vertical = 10.dp)
                        .testTag("chat_${c.id}"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    InitialsAvatar(c.name)
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 12.dp),
                    ) {
                        Text(c.name, style = MaterialTheme.typography.titleMedium)
                        Text(
                            c.preview,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                        )
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            c.time,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (c.unread > 0) {
                            Badge(modifier = Modifier.padding(top = 6.dp)) { Text(c.unread.toString()) }
                        }
                    }
                }
            }
        }
    }
}
