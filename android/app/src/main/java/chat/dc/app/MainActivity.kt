package chat.dc.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.core.content.ContextCompat
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import chat.dc.app.addfriend.AddFriendScreen
import chat.dc.app.nearby.NearbyScreen
import chat.dc.app.ui.chat.ChatScreen
import chat.dc.app.ui.contacts.ContactsScreen
import chat.dc.app.ui.me.MeScreen
import chat.dc.app.service.NodeService
import chat.dc.app.ui.messages.MessagesScreen
import chat.dc.app.ui.theme.DCChatTheme

/**
 * 底部导航三主 tab：消息 / 联系人 / 我的（排版结构参考微信，样式原创）。
 * 每个功能区一律独立子页面，不在主页面堆砌功能。
 */
class MainActivity : ComponentActivity() {
    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { startNodeService() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DCChatTheme {
                MainScaffold()
            }
        }
        ensureNodeService()
    }

    /** 「人人即节点」：进入应用即启动前台服务（用户可关）。
     *  通知权限被拒也照常启动——服务照跑，只是常驻通知不显示。
     *  残留#4 修复：启动动作只在权限回调里执行一次，避免双启动。 */
    private fun ensureNodeService() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startNodeService()
        }
    }

    private fun startNodeService() {
        ContextCompat.startForegroundService(this, Intent(this, NodeService::class.java))
    }
}

private data class Tab(
    val route: String,
    val labelRes: Int,
    val icon: @Composable () -> Unit,
)

@Composable
fun MainScaffold() {
    val tabs = listOf(
        Tab("messages", R.string.tab_messages) {
            Icon(Icons.Filled.ChatBubbleOutline, contentDescription = null)
        },
        Tab("contacts", R.string.tab_contacts) {
            Icon(Icons.Filled.People, contentDescription = null)
        },
        Tab("me", R.string.tab_me) {
            Icon(Icons.Filled.Person, contentDescription = null)
        },
    )
    val navController = rememberNavController()
    val backStack by navController.currentBackStackEntryAsState()
    val currentDestination = backStack?.destination

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                tabs.forEach { tab ->
                    val selected = currentDestination?.hierarchy?.any { it.route == tab.route } == true
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            navController.navigate(tab.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = tab.icon,
                        label = { Text(stringResource(tab.labelRes)) },
                        modifier = Modifier.testTag("tab_${tab.route}"),
                    )
                }
            }
        },
    ) { innerPadding ->
        // P1 速度感（Telegram）：全导航统一 200ms 淡入轻移，退场更快（150ms）
        NavHost(
            navController = navController,
            startDestination = "messages",
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            enterTransition = {
                androidx.compose.animation.fadeIn(androidx.compose.animation.core.tween(200)) +
                    androidx.compose.animation.slideInHorizontally(
                        androidx.compose.animation.core.tween(200),
                    ) { it / 8 }
            },
            exitTransition = { androidx.compose.animation.fadeOut(androidx.compose.animation.core.tween(150)) },
            popEnterTransition = { androidx.compose.animation.fadeIn(androidx.compose.animation.core.tween(200)) },
            popExitTransition = {
                androidx.compose.animation.fadeOut(androidx.compose.animation.core.tween(150)) +
                    androidx.compose.animation.slideOutHorizontally(
                        androidx.compose.animation.core.tween(150),
                    ) { it / 8 }
            },
        ) {
            composable("messages") {
                MessagesScreen(
                    onOpenChat = { id -> navController.navigate("chat/$id") },
                    onOpenAddFriend = { navController.navigate("add_friend") },
                )
            }
            composable("contacts") {
                ContactsScreen(
                    onOpenNearby = { navController.navigate("nearby") },
                    onOpenAddFriend = { navController.navigate("add_friend") },
                    onOpenChat = { id -> navController.navigate("chat/$id") },
                )
            }
            composable("me") {
                MeScreen(onOpenAddFriend = { navController.navigate("add_friend") })
            }
            composable("nearby") { NearbyScreen() }
            composable("add_friend") { AddFriendScreen() }
            composable(
                route = "chat/{contactId}",
                arguments = listOf(navArgument("contactId") { type = NavType.StringType }),
            ) {
                ChatScreen(
                    onBack = { navController.popBackStack() },
                    onAddFriend = { navController.navigate("add_friend") },
                )
            }
        }
    }
}
