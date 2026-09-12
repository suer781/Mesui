package chat.dc.app.testing

import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * JVM/Robolectric 测试桩：提供名为 AndroidKeyStore 的内存 KeyStore 与 AES KeyGenerator。
 * 真机走硬件 Keystore（不可导出）；纯 JVM 测试环境没有该 provider，
 * SignalCore/IrohNodeManager 的「Keystore 包裹落盘」路径会在 KeyStore.getInstance 处直接抛异常，
 * 导致依赖真实 UI 的 Robolectric 用例无法运行。本桩让同一条代码路径在测试中可走通。
 */
object FakeAndroidKeyStore {
    @Volatile private var installed = false

    @Synchronized
    fun install() {
        if (installed) return
        Security.addProvider(
            object : Provider("AndroidKeyStore", 1.0, "内存测试桩（替代硬件 Keystore，仅测试环境注册）") {
                init {
                    put("KeyStore.AndroidKeyStore", MemoryKeyStoreSpi::class.java.name)
                    put("KeyGenerator.AES", FixedAesKeyGeneratorSpi::class.java.name)
                }
            },
        )
        installed = true
    }
}

/** 内存 KeyStore：SignalCore 只用 load(null) + getKey，其余操作一概拒绝。 */
private class MemoryKeyStoreSpi : KeyStoreSpi() {
    private val keys = HashMap<String, SecretKey>()

    override fun engineLoad(stream: java.io.InputStream?, password: CharArray?) { /* 内存库：无持久化 */ }

    override fun engineLoad(param: java.security.KeyStore.LoadStoreParameter?) { /* 兼容重载 */ }

    override fun engineGetKey(alias: String?, password: CharArray?): Key? = keys[alias]

    override fun engineSetKeyEntry(alias: String?, key: Key, password: CharArray?, chain: Array<out Certificate>?) {
        (key as? SecretKey)?.let { keys[alias!!] = it }
    }

    override fun engineSetKeyEntry(
        alias: String?,
        key: ByteArray,
        chain: Array<out Certificate>?,
    ) = throw UnsupportedOperationException("测试桩不支持加密私钥条目")

    override fun engineDeleteEntry(alias: String?) { keys.remove(alias) }

    override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys)

    override fun engineContainsAlias(alias: String?): Boolean = keys.containsKey(alias)

    override fun engineSize(): Int = keys.size

    override fun engineIsKeyEntry(alias: String?): Boolean = keys.containsKey(alias)

    override fun engineIsCertificateEntry(alias: String?): Boolean = false

    override fun engineGetCertificate(alias: String?): Certificate? = null

    override fun engineGetCertificateAlias(cert: Certificate?): String? = null

    override fun engineGetCertificateChain(alias: String?): Array<Certificate> = arrayOf()

    override fun engineGetCreationDate(alias: String?): Date? = null

    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) =
        throw UnsupportedOperationException("测试桩不支持证书条目")

    override fun engineStore(stream: OutputStream?, password: CharArray?) =
        throw UnsupportedOperationException("测试桩不支持持久化")
}

/** AES 生成桩：忽略 KeyGenParameterSpec（真机由其约束不可导出），给出等长随机 AES-256 key。 */
private class FixedAesKeyGeneratorSpi : KeyGeneratorSpi() {
    private var random = SecureRandom()
    private var keySizeBits = 256

    override fun engineInit(random: SecureRandom?) {
        if (random != null) this.random = random
    }

    override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {
        // KeyGenParameterSpec 的 size/用途约束在测试桩中省略，只保留默认 256 位
        engineInit(random)
    }

    override fun engineInit(keysize: Int, random: SecureRandom?) {
        keySizeBits = keysize
        engineInit(random)
    }

    override fun engineGenerateKey(): SecretKey {
        val bytes = ByteArray(keySizeBits / 8).also { random.nextBytes(it) }
        return SecretKeySpec(bytes, "AES")
    }
}
