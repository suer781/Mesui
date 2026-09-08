package chat.dc.app.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import chat.dc.app.ble.BleMesh
import chat.dc.core.IrohNode
import chat.dc.core.NodeCallback
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** iroh 节点运行快照（Me 页节点面板与发送降级判定用）。 */
data class IrohSnap(
    val running: Boolean = false,
    val nodeIdHex: String = "",
    val naddr: String = "",
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

    private const val KEYSTORE_ALIAS = "dc-node-seed"
    private const val SEED_FILE = "dc.nodekey"
    private const val PREFS = "dc-settings"
    private const val PREF_RELAY = "relay_url"
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow(IrohSnap())
    val state = _state.asStateFlow()

    @Volatile private var node: IrohNode? = null
    @Volatile private var appContext: Context? = null
    @Volatile private var starting = false

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

    /** 启动（幂等）：已在跑或正在启动则忽略。 */
    fun start(context: Context) {
        if (node != null || starting) return
        starting = true
        appContext = context.applicationContext
        scope.launch {
            try {
                val seed = nodeSeed(context)
                val relay = relayUrl(context)
                val callback = object : NodeCallback {
                    override fun onMessage(fromNodeIdHex: String, payload: ByteArray) {
                        val ctx = appContext ?: return
                        val contact = runCatching {
                            SignalCore.contactStore(ctx).listContacts().firstOrNull { it.nodeId == fromNodeIdHex }
                        }.getOrNull() ?: return
                        BleMesh.deliverRemote(contact.name, payload)
                    }

                    override fun onReady(nodeIdHex: String, naddr: String) {
                        _state.value = IrohSnap(running = true, nodeIdHex = nodeIdHex, naddr = naddr)
                    }
                }
                node = IrohNode.start(relay, seed, callback)
            } catch (_: Exception) {
                // 无网/端口异常等：保持未运行态，下次 start 或服务重建再试
                _state.value = IrohSnap()
            } finally {
                starting = false
            }
        }
    }

    /** 停止并清理快照（NodeService.onDestroy / 中继变更重启时调用）。 */
    fun stop() {
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
