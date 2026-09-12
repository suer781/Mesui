package chat.dc.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import chat.dc.app.R
import chat.dc.app.ble.BleMesh
import chat.dc.app.core.IrohNodeManager
import chat.dc.app.core.SignalCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch

/**
 * 前台服务：Rust 节点（iroh endpoint）与蓝牙链路的常驻宿主。
 * 保活策略：常驻通知，用户可关（默认开）。
 * BLE mesh（广播/扫描/回连/配对）与 iroh 远程收发均由此常驻驱动；
 * 离线信箱补投、联系人间中继为后续阶段。
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

    // 重初始化在后台协程执行；onDestroy 时取消，避免销毁后仍操作 mesh/iroh
    private val initScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        // Android 12+ 对前台服务启动有约 5 秒死线（ForegroundServiceDidNotStartInTimeException），
        // 而 SignalCore.session 首开 SQLCipher（含 KDF 运算）弱机上可能超时 → 必须
        // 先 ensureChannel + startForeground 占位合规，重初始化整体挪进后台协程。
        ensureChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        initScope.launch {
            // 启动即生成 Signal 会话（应用级单例；runCatching 防止个别机型
            // native 加载失败导致前台服务崩溃循环，页面首次访问时仍会重试）
            runCatching { SignalCore.session(this@NodeService) }
                .onFailure { android.util.Log.w("NodeService", "Signal 会话初始化失败（页面访问时会重试）", it) }
            // 下面两步都是阻塞调用、无挂起点，cancel() 只能等它们返回后生效：
            // 在每个步骤边界主动检查，避免服务已 onDestroy 仍把 mesh/iroh 重新拉起来
            // （否则会以新代次起节点、活在 IrohNodeManager 的 scope 里 = 销毁后复活）
            ensureActive()
            runCatching { BleMesh.init(this@NodeService) }
                .onFailure { android.util.Log.w("NodeService", "BLE mesh 初始化失败", it) }
            ensureActive()
            // iroh 远程节点：端点常驻（QUIC 直连 + 可选自建中继），联系人间跨网络收发；
            // 启动失败的自愈退避重试由 IrohNodeManager 内部负责
            runCatching { IrohNodeManager.start(this@NodeService) }
                .onFailure { android.util.Log.w("NodeService", "iroh 节点启动失败（内部有退避重试）", it) }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // 先取消在途初始化协程，再停 mesh/iroh，避免销毁后仍被拉起
        initScope.cancel()
        // START_STICKY 重建时 mesh/iroh 随新实例 init；进程真退出则无线程可留
        runCatching { BleMesh.shutdown() }
        runCatching { IrohNodeManager.stop() }
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
