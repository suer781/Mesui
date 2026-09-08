package chat.dc.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import chat.dc.app.R
import chat.dc.app.core.SignalCore

/**
 * 前台服务：Rust 节点（iroh endpoint + 信箱桶 + 联系人间中继）与蓝牙
 * 链路的常驻宿主。保活策略：常驻通知，用户可关（默认开）。
 * 接入 UniFFI 核心句柄后实现真正逻辑；当前为占位。
 */
class NodeService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * START_STICKY：服务被系统杀死后自动重建——节点级的「重试循环」，
     * 与 Rust 侧消息级重试（retry.rs + 队列 next_attempt_ms）互补成两级自愈。
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        return START_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        // 启动即生成 Signal 会话（应用级单例；runCatching 防止个别机型
        // native 加载失败导致前台服务崩溃循环，页面首次访问时仍会重试）
        runCatching { SignalCore.session(this) }
        ensureChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    /** 常驻通知渠道（minSdk 26 = O，无需版本判断；无渠道 startForeground 会丢通知）。 */
    private fun ensureChannel() {
        val channel = NotificationChannel(
            NODE_CHANNEL_ID,
            getText(R.string.node_service_title),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, NODE_CHANNEL_ID)
            // 常驻通知只显示应用名，无第二行内容
            .setContentTitle(getText(R.string.app_name))
            .setSmallIcon(applicationInfo.icon)
            .setOngoing(true)
            .build()

    companion object {
        const val NODE_CHANNEL_ID = "node_service"
        const val NOTIFICATION_ID = 1
    }
}
