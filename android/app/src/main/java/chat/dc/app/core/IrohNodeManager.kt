package chat.dc.app.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import chat.dc.app.ble.BleMesh
import chat.dc.core.IrohNode
import chat.dc.core.NodeCallback
import java.io.File
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** iroh 节点启动状态机（自愈重试用）。 */
enum class IrohStatus { IDLE, STARTING, RETRYING, RUNNING, FAILED }

/** iroh 节点运行快照（Me 页节点面板与发送降级判定用）。 */
data class IrohSnap(
    val running: Boolean = false,
    val nodeIdHex: String = "",
    val naddr: String = "",
    // 启动/自愈重试状态：消费方（Me 页等）未消费该字段时行为与旧版一致
    val status: IrohStatus = IrohStatus.IDLE,
)

/**
 * iroh 远程节点管理器（应用级单例）：NodeService 常驻驱动的跨网络通道。
 *
 * - 节点种子 32 字节随机，经 AndroidKeyStore AES-GCM 加密落盘（与 SQLCipher
 *   库密钥同一保护模式），重启沿用 → 节点 id 稳定，联系人侧 QR 快照长期有效
 * - 自建中继 URL 存 SharedPreferences（「节点服务」面板可改，保存即重启生效）；
 *   空 = 禁用中继（v9 默认，同 WiFi/热点直连；跨网需自建中继）
 * - onMessage：按节点 id 反查联系人 → 交给 BleMesh 统一解密落库 + 入站流
 */
object IrohNodeManager {

    private const val TAG = "IrohNodeManager"
    private const val KEYSTORE_ALIAS = "dc-node-seed"
    private const val SEED_FILE = "dc.nodekey"
    private const val PREFS = "dc-settings"
    private const val PREF_RELAY = "relay_url"
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128

    // 启动自愈重试：失败后 5s/15s/45s 指数退避，最多重试 3 次（首发失败之后）
    private const val RETRY_MAX = 3
    private val RETRY_DELAYS_MS = longArrayOf(5_000L, 15_000L, 45_000L)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow(IrohSnap())
    val state = _state.asStateFlow()

    @Volatile private var node: IrohNode? = null
    @Volatile private var appContext: Context? = null
    // 启动权标志（P3）：无锁双入竞态下「读到 false → 置 true」的 check-then-act
    // 会让两个线程各拉起一个 iroh 节点（端口/资源冲突，旧节点成孤儿）。CAS 保证
    // 全局只有一个启动协程能持有启动权
    private val starting = AtomicBoolean(false)
    // 启动代次：stop() 自增使在途的启动/重试协程失效，防止 stop 后被旧协程重新拉起
    @Volatile private var startGen = 0L

    // 缺陷 C：nodeId→联系人名 缓存，避免每条入站消息全表 listContacts() 线性反查。
    // 命中 O(1)；未命中时按 listContacts 重建一次（联系人增改后下次未命中自动刷新）。
    private val nodeIdIndex = ConcurrentHashMap<String, String>()

    /** 自建中继 URL（空 = 禁用）。 */
    fun relayUrl(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(PREF_RELAY, "") ?: ""

    /** 保存中继 URL 并重启节点使其生效。 */
    fun setRelayUrlAndRestart(context: Context, url: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(PREF_RELAY, url.trim()).apply()
        stop()
        start(context)
    }

    /** 启动（幂等）：已在跑或正在启动则忽略；失败按 5s/15s/45s 退避自愈重试，最多 3 次。 */
    fun start(context: Context) {
        if (node != null) return
        if (!starting.compareAndSet(false, true)) return
        appContext = context.applicationContext
        val gen = startGen
        scope.launch {
            try {
                val callback = object : NodeCallback {
                    override fun onMessage(fromNodeIdHex: String, payload: ByteArray) {
                        // 世代守卫：本回调属于某一代启动，stop() 换代后到达的消息不再投递
                        if (gen != startGen) return
                        // 本回调运行在 iroh 的 tokio worker 线程（node.rs 仅 2 个 worker）：
                        // 同步做 SQLite 全表反查 + 解密会拖垮端点调度（心跳/建连），
                        // 故投递到 IO 线程执行，绝不阻塞 iroh 线程（缺陷 B）。
                        scope.launch {
                            if (gen != startGen) return@launch
                            val ctx = appContext ?: return@launch
                            val name = resolveNameByNodeId(ctx, fromNodeIdHex) ?: return@launch
                            BleMesh.deliverRemote(name, payload)
                        }
                    }

                    override fun onReady(nodeIdHex: String, naddr: String) {
                        // 世代守卫：原生 start 可能仍在跑时发生 stop()，其 onReady 迟到会
                        // 把已清空的快照写回 running=true（Me 页显示「运行中」但 node 已为 null）
                        if (gen != startGen) return
                        _state.value = IrohSnap(running = true, nodeIdHex = nodeIdHex, naddr = naddr, status = IrohStatus.RUNNING)
                    }
                }
                // 首发 + 指数退避自愈：NodeService 仅在 onCreate 调一次 start，
                // 此前失败被 runCatching 静默吞掉后无任何路径再拉起，节点直到进程
                // 重启都是死的；无网/端口占用等多为瞬时故障，退避重试即可自愈。
                for (attempt in 0..RETRY_MAX) {
                    if (gen != startGen) break  // stop() 已打断本轮启动
                    // 首发标「启动中」，退避重试标「重试中」；旧消费方只看 running，不受影响
                    _state.value =
                        if (attempt == 0) IrohSnap(status = IrohStatus.STARTING)
                        else IrohSnap(status = IrohStatus.RETRYING)
                    if (attempt > 0) delay(RETRY_DELAYS_MS[attempt - 1])
                    if (gen != startGen) break  // 退避期间发生 stop()
                    try {
                        val ctx = appContext ?: break
                        val seed = nodeSeed(ctx)
                        val relay = relayUrl(ctx)
                        val created = IrohNode.start(relay, seed, callback)
                        // 原生 start 阻塞期间若发生 stop()：立即回收，避免遗留无人管的节点
                        if (gen != startGen) {
                            runCatching { created.stop() }
                            break
                        }
                        node = created
                        break  // 启动成功（RUNNING 态由 onReady 回调写入）
                    } catch (e: CancellationException) {
                        // 协程取消（如退出/重建）不是启动失败：不吞，交回结构化并发语义
                        throw e
                    } catch (e: Exception) {
                        // 本轮失败：退避后重试；重试耗尽则标「失败」，等
                        // setRelayUrlAndRestart 或服务重建（START_STICKY）再拉起
                        android.util.Log.w(TAG, "iroh 节点启动失败（第 ${attempt + 1} 次）", e)
                        if (attempt == RETRY_MAX) _state.value = IrohSnap(status = IrohStatus.FAILED)
                    }
                }
            } finally {
                // 仅当代次未变时清 flag：stop→start 换代后，新启动协程持有该 flag
                if (gen == startGen) starting.set(false)
            }
        }
    }

    /** 停止并清理快照（NodeService.onDestroy / 中继变更重启时调用）。 */
    fun stop() {
        // 换代 + 释放 starting：让在途启动/重试协程失效，setRelayUrlAndRestart
        // 紧随其后的 start() 不再被旧协程的 starting flag 挡掉
        startGen++
        starting.set(false)
        val n = node
        node = null
        _state.value = IrohSnap()
        if (n != null) scope.launch { runCatching { n.stop() } }
    }

    /**
     * 按联系人快照发送（阻塞至对端应用层确认）。调用方放 IO 线程；
     * 节点未运行或对端不可达返回 false（UI 显示发送失败）。
     */
    fun send(naddr: String, payload: ByteArray, timeoutMs: UInt = 20_000u): Boolean {
        val n = node ?: return false
        return runCatching { n.send(naddr, payload, timeoutMs) }.isSuccess
    }

    /** 节点是否在跑（发送降级判定）。 */
    fun isRunning(): Boolean = node != null

    /**
     * 按 nodeId 反查联系人名：先走 [nodeIdIndex] 缓存（O(1)），未命中再按 listContacts
     * 重建一次（缺陷 C）。联系人增改后下次未命中自动刷新，避免每条入站消息全表扫描。
     */
    private fun resolveNameByNodeId(context: Context, nodeIdHex: String): String? {
        nodeIdIndex[nodeIdHex]?.let { return it }
        synchronized(nodeIdIndex) {
            nodeIdIndex.clear()
            runCatching { SignalCore.contactStore(context).listContacts() }
                .getOrDefault(emptyList())
                .forEach { nodeIdIndex[it.nodeId] = it.name }
        }
        return nodeIdIndex[nodeIdHex]
    }

    /**
     * 联系人删除/变更后作废 [nodeIdIndex]（P2）：缓存只在「未命中」时重建，
     * 删联系人不会造成未命中——旧映射 nodeId→已删联系人名 一直命中，消息仍被
     * 投递给已删联系人。SignalCore 的 store 删除钩子代调本方法。
     */
    fun invalidateNodeIdIndex() {
        nodeIdIndex.clear()
    }

    // ---------------- 节点种子持久化（Keystore AES-GCM 包裹，同 SignalCore 库密钥模式） ----------------

    private fun keystoreKey(): javax.crypto.SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEYSTORE_ALIAS, null) as? javax.crypto.SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private fun nodeSeed(context: Context): ByteArray {
        val file = File(context.filesDir, SEED_FILE)
        val key = keystoreKey()
        if (file.exists()) {
            val blob = file.readBytes()
            if (blob.size > GCM_IV_LEN) {
                val plain = runCatching {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_LEN))
                    cipher.doFinal(blob, GCM_IV_LEN, blob.size - GCM_IV_LEN)
                }.getOrNull()
                if (plain != null && plain.size == 32) return plain
            }
            // 解不开 = Keystore 与密文不匹配：轮换节点密钥。旧联系人按快照
            // 找不到我们 → 对方发不来；重扫码即刷新双方快照。
            file.delete()
        }
        val seed = ByteArray(32).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        file.writeBytes(cipher.iv + cipher.doFinal(seed))
        return seed
    }
}
