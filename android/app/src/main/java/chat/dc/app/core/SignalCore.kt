package chat.dc.app.core

import android.content.Context
import android.provider.Settings
import chat.dc.core.SignalSession
import java.util.UUID

/**
 * Signal 会话的应用级持有者（阶段 0）：进程内单例，首次访问时
 * `SignalSession.generate(deviceName)` 生成长期身份密钥。
 * 持久化 store（SQLCipher）在阶段 3 接入——当前为内存实现，
 * 进程重启即换身份，属已知现状。
 *
 * deviceName 同时用作 ProtocolAddress 名与 SAS 的本地标识：
 * 对端从 QR 载荷读得同一字符串（AddFriendPayload.name），
 * 两端 sas_with 传入相同的 (local, remote) 名字对才能算出一致的 SAS。
 */
object SignalCore {
    /** 地址名规范：URL 安全、无 &/= 等会破坏 dc:// URI 解析的字符。 */
    val NAME_RE = Regex("[A-Za-z0-9._-]{1,64}")

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

    @Synchronized
    fun session(context: Context): SignalSession =
        session ?: SignalSession.generate(deviceName(context)).also { session = it }
}
