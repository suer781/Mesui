package chat.dc.app

import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 主界面运行时冒烟（Robolectric + Compose，JVM 真渲染）：
 * 启动真实 MainActivity → 底部三 tab → 联系人 tab → 「发现附近设备」子页权限引导。
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MainScaffoldTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun messages_tab_shows_empty_state_without_demo_data() {
        // 消息页展示引导空态，不再渲染演示会话与气泡
        compose.onNodeWithText("还没有会话").assertExists()
        compose.onNodeWithText("阿明").assertDoesNotExist()
        compose.onNodeWithText("现在方便说吗？").assertDoesNotExist()
        compose.onNodeWithTag("new_chat").assertExists()
        // 空态行动按钮 → 添加好友「选角色」入口（出示/扫码二选一，不同屏）
        compose.onNodeWithText("去添加好友").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("role_show").assertExists()
        compose.onNodeWithTag("role_scan").assertExists()
    }

    @Test
    fun me_tab_renders_profile_and_settings() {
        compose.onNodeWithTag("tab_me").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("me_qr").assertExists()
        compose.onNodeWithText("隐私与安全").assertExists()
        compose.onNodeWithText("节点服务").assertExists()
    }

    @Test
    fun add_friend_role_show_renders_dynamic_qr_only() {
        compose.onNodeWithTag("tab_contacts").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("open_add_friend").performClick()
        compose.waitForIdle()
        // 入口是选角色页：出示与扫码绝不同屏
        compose.onNodeWithTag("role_show").assertExists()
        compose.onNodeWithTag("role_scan").assertExists()
        // 选「出示我的码」→ 只有动态码，没有取景器
        compose.onNodeWithTag("role_show").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("qr_image").assertExists()
        compose.onNodeWithTag("scan_view").assertDoesNotExist()
    }

    @Test
    fun add_friend_role_scan_without_camera_shows_grant_button() {
        compose.onNodeWithTag("tab_contacts").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("open_add_friend").performClick()
        compose.waitForIdle()
        // 选「扫码添加」→ 无相机权限时显示授权按钮，且没有「我的动态码」
        compose.onNodeWithTag("role_scan").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("grant_camera").assertExists()
        compose.onNodeWithTag("qr_image").assertDoesNotExist()
    }

    @Test
    fun nearby_flow_shows_permission_guidance() {
        compose.onNodeWithTag("tab_contacts").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("open_nearby").performClick()
        compose.waitForIdle()

        // NearbyScreen 无权限态文案（Robolectric 无蓝牙权限）。
        // 注：导航转场在 Robolectric 时钟下不结束，节点存在但 display=false，
        // 故流程断言用存在性；「显示」只在静止的底栏上断言。
        compose.onNodeWithText("需要附近的设备权限才能扫描蓝牙节点").assertExists()
        compose.onNodeWithText("授予权限").assertExists()
    }
}
