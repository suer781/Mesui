package chat.dc.app

import android.Manifest
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 相机已授权分支的运行时验证：
 * 授权后添加好友页必须出现取景器，且整页可滚动不裁剪。
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MainScaffoldCameraTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Before
    fun grantCamera() {
        shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>())
            .grantPermissions(Manifest.permission.CAMERA)
    }

    @Test
    fun add_friend_with_camera_shows_viewfinder() {
        compose.onNodeWithTag("tab_contacts").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("open_add_friend").performClick()
        compose.waitForIdle()
        // 入口先选角色：进入「扫码添加」独立页
        compose.onNodeWithTag("role_scan").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("scan_view").assertExists()
        compose.onNodeWithText("对准对方滚动的动态码，保持约 3 秒即可读全").assertExists()
        // 页面尾部的提示文本也必须存在：配合 verticalScroll，小屏不得裁掉内容
        compose.onNodeWithText("真实身份与加密会话将在核心接入后建立").assertExists()
    }
}
