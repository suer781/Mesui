package chat.dc.app.core

import android.content.Context
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128

    @Volatile
    private var cachedName: String? = null

    @Volatile
    private var session: SignalSession? = null

    fun deviceName(context: Context): String =
        cachedName ?: run {
            val id = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            val name = if (id != null && NAME_RE.matches(id)) id else "dc-" + UUID.randomUUID().toString().take(16)
            cachedName = name
            name
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
            if (blob.size > GCM_IV_LEN) {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_LEN))
                return cipher.doFinal(blob, GCM_IV_LEN, blob.size - GCM_IV_LEN)
                    .toString(Charsets.US_ASCII) // 存的就是 hex ASCII
            }
        }
        // 首次：32 字节随机 → hex(64 字符，无引号，SQLCipher PRAGMA key 安全)
        val hex = ByteArray(32).also(SecureRandom()::nextBytes)
            .joinToString("") { "%02x".format(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        file.writeBytes(cipher.iv + cipher.doFinal(hex.toByteArray(Charsets.US_ASCII)))
        return hex
    }

    /** 持久化 SignalSession：身份/会话/TOFU pin 落盘，重启沿用。 */
    @Synchronized
    fun session(context: Context): SignalSession =
        session ?: SignalSession.open(
            File(context.filesDir, DB_FILE).absolutePath,
            dbKeyHex(context),
            deviceName(context),
        ).also { session = it }
}
