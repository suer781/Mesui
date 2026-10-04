package chat.dc.app.core

import android.content.Context
import android.util.Log
import chat.dc.app.ble.BleMesh
import chat.dc.app.ble.PeerState
import chat.dc.core.DeliveryManagerHandle
import chat.dc.core.SendCallback
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.io.File
import java.security.SecureRandom

/**
 * 加密投递队列桥（Phase A「离线消息不丢」的 Kotlin 接线）。
 *
 * 职责：
 * - 打开 Rust `DeliveryManagerHandle`（SQLCipher outbox，`queue.rs` + `delivery.rs`）；
 * - `BleMesh.sendText` 两路都不通时经 [enqueue] 把已加密载荷写入 outbox；
 * - 周期 `tick()`（前台服务驱动，默认 20 秒）把到期消息交回发送通道补投；
 * - BLE 好友上线 / iroh 节点就绪时立即 `tick()`（重连即补投）。
 *
 * 发送通道由 `EnvelopeSender` 注入（NodeService 组装 BleMesh.sendEnvelope）。
 * 回调语义对齐 Rust `SendFn`：返回 true = 已送达；false = 不可达（按退避重试）；
 * 抛异常 = 通道故障（Rust tick 内 catch_unwind 保护，同样按退避重试）。
 * 红线：`SendCallback` 实现内绝不调用本桥/句柄方法（tick 持锁发送期间重入
 * 会死锁 Mutex）——回调只做「解析信封 → 交给 EnvelopeSender 发送」。
 */
object DeliveryBridge {

    private const val TAG = "DeliveryBridge"
    private const val OUTBOX_DB = "dc-outbox.db"

    /** 周期补投间隔（任务要求 15-30 秒；与默认退避 base_delay 2s 兼容）。 */
    private const val TICK_INTERVAL_MS = 20_000L

    /** 每日清理：过期去重台账 + 已发送行 + 死信。 */
    private const val CLEANUP_INTERVAL_MS = 24L * 60 * 60 * 1000L

    /** 实际发送通道（BleMesh 注册）：recipient 为信封 32 字节收件方标识。 */
    fun interface EnvelopeSender {
        /** 尝试发送已加密载荷；返回 true = 已送达，false = 对方当前不可达。 */
        fun send(recipientNodeId: ByteArray, payload: ByteArray): Boolean
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val random = SecureRandom()

    @Volatile private var handle: DeliveryManagerHandle? = null
    @Volatile private var appContext: Context? = null
    @Volatile private var sender: EnvelopeSender? = null
    @Volatile private var tickJob: Job? = null
    private val watchJobs = mutableListOf<Job>()
    @Volatile private var lastCleanupMs = System.currentTimeMillis()

    /** 是否已启动（NodeService 生命周期内）。 */
    val isStarted: Boolean get() = handle != null

    /** 启动：打开（或创建）加密 outbox 并接上发送通道；幂等。 */
    @Synchronized
    fun start(context: Context, sender: EnvelopeSender) {
        if (handle != null) return
        appContext = context.applicationContext
        this.sender = sender
        val h = openHandle()
        if (h == null) {
            Log.w(TAG, "打开投递队列失败：离线消息将无法入队（进程重启后自动重试）")
            return
        }
        handle = h
        lastCleanupMs = System.currentTimeMillis()
        startTicker()
        startWatchers()
    }

    /** 停止并关闭句柄（NodeService.onDestroy）。 */
    @Synchronized
    fun stop() {
        tickJob?.cancel()
        tickJob = null
        watchJobs.forEach { it.cancel() }
        watchJobs.clear()
        val h = handle
        handle = null
        h?.close()
        sender = null
        appContext = null
    }

    /**
     * 把已加密载荷写入 outbox（`BleMesh.sendText` 两路失败时调用）。
     * 返回 true = 入队成功；随后在后台协程立即 tick 一拍（Rust 语义：
     * 「每次 enqueue 后调用 tick」），消息随后由周期 tick / 上线事件补投。
     */
    fun enqueue(peerName: String, payload: ByteArray): Boolean {
        val ctx = appContext ?: return false
        val contact = runCatching {
            SignalCore.contactStore(ctx).listContacts().firstOrNull { it.name == peerName }
        }.getOrNull() ?: return false
        val recipient = contactKey(contact.identity) ?: return false
        val h = handleOrOpenLazy() ?: run {
            Log.w(TAG, "投递队列未就绪，消息无法入队（peer=$peerName）")
            return false
        }
        val json = EnvelopeJson.buildText(
            msgId = ByteArray(16).also(random::nextBytes),
            sender = senderNodeIdBytes(),
            recipient = recipient,
            body = payload,
            sentAtMs = System.currentTimeMillis(),
        )
        val ok = runCatching { h.enqueue(json) }
            .onFailure { Log.w(TAG, "消息入队失败（peer=$peerName）", it) }
            .isSuccess
        if (ok) scope.launch { tick() }
        return ok
    }

    /** 投递一拍：到期消息交发送通道；成功出队，失败按退避重试，耗尽转死信。 */
    fun tick() {
        val h = handle ?: return
        runCatching {
            val rep = h.tick(System.currentTimeMillis().toULong())
            if (rep.dead > 0u || rep.errored > 0u) {
                Log.w(
                    TAG,
                    "tick 结果：尝试 ${rep.attempted}，送达 ${rep.sent}，" +
                        "不可达 ${rep.unreachable}，错误 ${rep.errored}，死信 ${rep.dead}",
                )
            }
        }.onFailure { Log.w(TAG, "tick 失败", it) }
    }

    /** 每日清理：过期去重台账 + 已发送行 + 死信（低频，随周期任务触发）。 */
    fun cleanup() {
        val h = handle ?: return
        runCatching { h.cleanup(System.currentTimeMillis().toULong()) }
            .onFailure { Log.w(TAG, "cleanup 失败", it) }
    }

    /** (待发, 死信, 已见去重) 计数；未启动返回空列表。 */
    fun stats(): List<UInt> = runCatching { handle?.stats() }.getOrNull() ?: emptyList()

    /** 死信清单（msg_id hex，按创建序；UI「再试一次」列表用）。 */
    fun deadLetters(limit: UInt = 50u): List<String> =
        runCatching { handle?.deadLetters(limit) }.getOrNull() ?: emptyList()

    /** 复活死信（attempts 归零重新计入退避）。 */
    fun revive(msgIdHex: String): Boolean =
        runCatching { handle?.revive(msgIdHex); true }.getOrDefault(false)

    private fun openHandle(): DeliveryManagerHandle? {
        val ctx = appContext ?: return null
        val dbFile = File(ctx.filesDir, OUTBOX_DB)
        val path = dbFile.absolutePath
        val key = SignalCore.outboxKeyHex(ctx)
        val callback = object : SendCallback {
            override fun send(envelopeJson: String): Boolean {
                val env = EnvelopeJson.parse(envelopeJson) ?: return false
                val recipient = env.recipient ?: return false
                return this@DeliveryBridge.sender?.send(recipient, env.body) ?: false
            }
        }
        fun open(): DeliveryManagerHandle? = runCatching {
            DeliveryManagerHandle(path, key, callback)
        }.onFailure { Log.w(TAG, "打开投递队列失败", it) }.getOrNull()
        val h = open()
        if (h != null) return h
        // 密钥轮换（Keystore 重置）或库损坏：旧库无法用新密钥打开。
        // 删除后重建，避免队列永久不可用（待发密文随之丢失，但 Signal 库
        // 在同一重置场景下本就会清空，属可接受的降级）。
        Log.w(TAG, "投递队列无法打开，删除损坏库后重建")
        dbFile.delete()
        return open()
    }

    /** 返回句柄；未启动或打开失败时尝试补开一次（NodeService 启动顺序错位自愈）。 */
    private fun handleOrOpenLazy(): DeliveryManagerHandle? {
        handle?.let { return it }
        synchronized(this) {
            handle?.let { return it }
            if (appContext == null || sender == null) return null
            return openHandle().also { handle = it }
        }
    }

    private fun startTicker() {
        tickJob?.cancel()
        tickJob = scope.launch {
            while (true) {
                delay(TICK_INTERVAL_MS)
                tick()
                val now = System.currentTimeMillis()
                if (now - lastCleanupMs >= CLEANUP_INTERVAL_MS) {
                    lastCleanupMs = now
                    cleanup()
                }
            }
        }
    }

    /** 上线/就绪事件 → 立即补投（任务要求的「重连时 tick」）。 */
    private fun startWatchers() {
        // BLE 链路从「无人上线」 → 「有人上线」：立即补投
        watchJobs += scope.launch {
            var wasOnline = false
            BleMesh.peers.collect { peers ->
                val nowOnline = peers.values.any { it == PeerState.ONLINE }
                if (nowOnline && !wasOnline) tick()
                wasOnline = nowOnline
            }
        }
        // iroh 节点从「未运行」 → 「运行」（跨网通道就绪）：立即补投
        watchJobs += scope.launch {
            var wasRunning = false
            IrohNodeManager.state.collect { snap ->
                if (snap.running && !wasRunning) tick()
                wasRunning = snap.running
            }
        }
    }

    /** 联系人 identity(33B = libsignal 类型前缀 + 32B) → 信封 recipient(32B)。 */
    private fun contactKey(identity: ByteArray): ByteArray? =
        when (identity.size) {
            33 -> identity.copyOfRange(1, 33)
            32 -> identity
            else -> null
        }

    /** 信封 sender 字段：本端 iroh 节点 id（hex → bytes）；未就绪用零占位。 */
    private fun senderNodeIdBytes(): ByteArray {
        val hex = IrohNodeManager.state.value.nodeIdHex
        if (hex.length == 64) {
            return hex.chunked(2).mapNotNull { it.toIntOrNull(16)?.toByte() }.toByteArray()
        }
        return ByteArray(32)
    }
}