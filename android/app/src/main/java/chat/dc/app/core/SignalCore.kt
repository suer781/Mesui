package chat.dc.app.core

import android.content.Context
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import chat.dc.core.ContactStore
import chat.dc.core.ContactStoreInterface
import chat.dc.core.SignalSession
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Signal 会话的应用级持有者：进程内单例。
 *
 * 持久化（阶段 3）：会话/身份/TOFU pin 落 SQLCipher 加密库
 * （filesDir/dc-signal.db），重启不丢；库密钥 32 字节随机，经
 * AndroidKeyStore 的 AES-GCM key 加密后存 filesDir/dc.dbkey
 * （Keystore key 不可导出，硬件保护；没有它无法解出库密钥）。
 *
 * deviceName 同时用作 ProtocolAddress 名与 SAS 的本地标识：
 * 对端从 QR 载荷读得同一字符串（AddFriendPayload.name），
 * 两端 sasWith 传入相同的 (local, remote) 名字对才能算出一致的 SAS。
 */
object SignalCore {
    /** 地址名规范：URL 安全、无 &/= 等会破坏 dc:// URI 解析的字符。 */
    val NAME_RE = Regex("[A-Za-z0-9._-]{1,64}")

    private const val KEYSTORE_ALIAS = "dc-sqlcipher"
    private const val KEY_FILE = "dc.dbkey"
    private const val DB_FILE = "dc-signal.db"
    private const val NAME_FILE = "dc.devicename"
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128

    @Volatile
    private var cachedName: String? = null

    @Volatile
    private var session: SignalSession? = null

    @Volatile
    private var contacts: ContactStoreInterface? = null

    // 解密失败自动重置的一次性提示位（UI consume 后清除）
    private var resetNoticePending = false

    fun deviceName(context: Context): String =
        cachedName ?: run {
            val id = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            val name = if (id != null && NAME_RE.matches(id)) id else persistedFallbackName(context)
            cachedName = name
            name
        }

    /** ANDROID_ID 不可用机型（部分厂商/工作资料/测试环境返回 null）的兜底名：
     *  随机生成一次后落盘复用（P3）。不持久化则每次进程重启换名——旧设备上的
     *  ProtocolAddress / SAS / 会话全部失配，等于每重启一次丢一次身份。 */
    @Synchronized
    private fun persistedFallbackName(context: Context): String {
        val file = File(context.filesDir, NAME_FILE)
        if (file.exists()) {
            runCatching { file.readText() }.getOrNull()
                ?.trim()
                ?.takeIf { NAME_RE.matches(it) }
                ?.let { return it }
        }
        val name = "dc-" + UUID.randomUUID().toString().take(16)
        runCatching { file.writeText(name) }
            .onFailure { android.util.Log.w("SignalCore", "设备兜底名落盘失败", it) }
        return name
    }

    /** Keystore 里的 AES-GCM key（不存在则生成；不可导出）。 */
    private fun keystoreKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }
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

    /** SQLCipher 库密钥（hex）：首次随机生成，Keystore 加密落盘后复用。 */
    @Synchronized
    private fun dbKeyHex(context: Context): String {
        val file = File(context.filesDir, KEY_FILE)
        val key = keystoreKey()
        if (file.exists()) {
            val blob = file.readBytes()
            val plain = runCatching {
                if (blob.size <= GCM_IV_LEN) error("dbkey truncated")
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_LEN))
                cipher.doFinal(blob, GCM_IV_LEN, blob.size - GCM_IV_LEN)
            }.getOrNull()
            if (plain != null) return String(plain, Charsets.US_ASCII) // 存的就是 hex ASCII
            // 解不开 = Keystore key 与密文不匹配（恢复出厂/换机恢复/库损坏）。
            // 无法找回旧库密钥：重置——删 key 文件与加密库，重新生成身份；
            // 会话/联系人/聊天记录全部丢失，UI 明示需重新扫码加好友。
            resetNoticePending = true
            file.delete()
            File(context.filesDir, DB_FILE).delete()
        }
        // 首次（或刚重置）：32 字节随机 → hex(64 字符，无引号，SQLCipher PRAGMA key 安全)
        val hex = ByteArray(32).also(SecureRandom()::nextBytes)
            .joinToString("") { "%02x".format(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        file.writeBytes(cipher.iv + cipher.doFinal(hex.toByteArray(Charsets.US_ASCII)))
        return hex
    }

    /** 取走「身份已自动重置」提示（一次性，true 后复位）。 */
    @Synchronized
    fun consumeIdentityResetNotice(): Boolean =
        resetNoticePending.also { resetNoticePending = false }

    /** 持久化 SignalSession：身份/会话/TOFU pin 落盘，重启沿用。 */
    @Synchronized
    fun session(context: Context): SignalSession {
        val dbFile = File(context.filesDir, DB_FILE)
        // 对称边界：key 在而库被外部删除——重建库等于新身份，同样须提示
        if (File(context.filesDir, KEY_FILE).exists() && !dbFile.exists()) {
            resetNoticePending = true
        }
        return session ?: SignalSession.open(
            dbFile.absolutePath,
            dbKeyHex(context),
            deviceName(context),
        ).also { session = it }
    }

    /** 联系人 + 聊天记录句柄：与 Signal store 同库同 key（不同表）。
     *  句柄外包一层删除钩子（P2-10）：删联系人必须同时作废 IrohNodeManager 的
     *  nodeId→名 反查缓存与 BleMesh 的扫描每槽缓存，否则已删联系人的消息
     *  仍按旧缓存命中被投递。委托作用于 ContactStoreInterface（接口）——
     *  ContactStore 本身是 uniffi 生成的 final class，不可继承。 */
    @Synchronized
    fun contactStore(context: Context): ContactStoreInterface =
        contacts ?: ContactStore.open(
            File(context.filesDir, DB_FILE).absolutePath,
            dbKeyHex(context),
        ).let { store ->
            object : ContactStoreInterface by store {
                override fun deleteContact(name: String) {
                    store.deleteContact(name)
                    IrohNodeManager.invalidateNodeIdIndex()
                    chat.dc.app.ble.BleMesh.invalidateScanCache()
                }
            }.also { contacts = it }
        }
}
