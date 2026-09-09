package chat.dc.app.addfriend

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.security.SecureRandom

/**
 * 加好友二维码载荷（二维码取代 NFC 成为带外引导通道）。
 *
 * 载荷 = dc://add?v=2 URI（阶段 0 起为真实密钥材料）：
 * - [name] 出示方地址名（ProtocolAddress + SAS 本地标识，对端原样回传）
 * - [identity] 出示方长期身份公钥（SAS/TOFU 锚点）：33 字节，即 libsignal
 *   `IdentityKey::serialize()`（1 字节曲线类型前缀 + 32 字节裸公钥），与
 *   `SignalSession.identityKey()` 返回值、Rust 侧 `IdentityKey::decode()` 入参为同一契约
 * - [bundle] PreKeyBundle 上线格式（CBOR，含 Kyber-1024 公钥，约 1.8KB）
 * - [bucket] 随机信箱桶地址
 * - [token] 单次 bootstrap token：带外秘密，首条消息须携带其 keyed-BLAKE3 MAC
 * - [ble] BLE 匹配 id：与 BLE 广播携带同一 id，扫码方据此定位设备（阶段 3）
 *
 * 身份↔节点密钥的绑定只在双方 Signal 会话内生效；token 单次有效。
 */
data class AddFriendPayload(
    val name: String,
    val identity: ByteArray,
    val bundle: ByteArray,
    val bucket: ByteArray,
    val token: ByteArray,
    val ble: ByteArray,
) {
    init {
        // 编码进 URI 前先断言，防止非法名破坏 dc://add 解析
        require(chat.dc.app.core.SignalCore.NAME_RE.matches(name)) { "bad name" }
        // 33 = libsignal IdentityKey::serialize()（1 字节类型前缀 + 32 字节公钥），见类注释
        require(identity.size == 33) { "identity must be 33 bytes" }
        require(bucket.size == 32) { "bucket must be 32 bytes" }
        require(token.size == 48) { "token must be 48 bytes" }
        require(ble.size == 8) { "ble must be 8 bytes" }
        require(bundle.size in 256..6144) { "bundle size out of range: ${bundle.size}" }
    }

    fun encode(): String {
        val b64 = { bytes: ByteArray -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) }
        return "dc://add?v=2&name=$name&id=${b64(identity)}&bundle=${b64(bundle)}" +
            "&bucket=${b64(bucket)}&token=${b64(token)}&ble=${b64(ble)}"
    }

    companion object {
        const val SCHEME_PREFIX = "dc://add?v=2&"

        fun parse(text: String): AddFriendPayload? {
            if (!text.startsWith(SCHEME_PREFIX)) return null
            val params = text.removePrefix(SCHEME_PREFIX).split('&')
                .mapNotNull {
                    val i = it.indexOf('=')
                    if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
                }
                .toMap()
            val name = params["name"]?.takeIf { chat.dc.app.core.SignalCore.NAME_RE.matches(it) } ?: return null
            val b64 = { s: String? ->
                s?.let { runCatching { java.util.Base64.getUrlDecoder().decode(it) }.getOrNull() }
            }
            val id = b64(params["id"]) ?: return null
            val bundle = b64(params["bundle"]) ?: return null
            val bucket = b64(params["bucket"]) ?: return null
            val token = b64(params["token"]) ?: return null
            val ble = b64(params["ble"]) ?: return null
            return runCatching { AddFriendPayload(name, id, bundle, bucket, token, ble) }.getOrNull()
        }
    }
}

object QrCodec {
    /** 生成方形二维码位图（纠错 M，容损 15%）。 */
    fun encode(content: String, size: Int): Bitmap {
        val matrix = QRCodeWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            size,
            size,
            mapOf(EncodeHintType.MARGIN to 1),
        )
        val bmp = Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.ARGB_8888)
        for (x in 0 until matrix.width) {
            for (y in 0 until matrix.height) {
                bmp.setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
        return bmp
    }
}

/**
 * 动态分帧二维码：
 * 载荷切成 N 个数据帧循环播放，混入随机噪声帧——单帧/单张截图不含完整信息；
 * 扫描端**持续采集，集齐全部数据帧且经过 ≥[MIN_COLLECT_MS] 才算完成**，
 * 完成后才允许进入蓝牙协商。
 */
object FrameCodec {
    const val MIN_COLLECT_MS: Long = 3_000
    const val FRAME_PREFIX = "dc://addframe?v=1&"

    // 真实载荷（含 ~1.8KB 的 PreKeyBundle）约 2.6KB；48 字符/帧会切出
    // 50+ 帧（30 秒以上才能集齐），故提到 256：约 11 帧，配合 3 秒
    // 时长门槛在 10 秒内可读全。单帧 QR 约 390 字符（版本 13），可扫。
    const val CHUNK_SIZE = 256

    fun split(payload: AddFriendPayload, sid: String): List<String> {
        val text = payload.encode()
        val n = (text.length + CHUNK_SIZE - 1) / CHUNK_SIZE
        return (0 until n).map { i ->
            val d = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                text.substring(i * CHUNK_SIZE, minOf((i + 1) * CHUNK_SIZE, text.length)).toByteArray(Charsets.UTF_8),
            )
            "${FRAME_PREFIX}s=$sid&i=$i&n=$n&f=1&d=$d"
        }
    }

    /** 噪声帧：随机内容、f=0，扫描端必须忽略——让单帧截屏失去意义。 */
    fun noiseFrame(sid: String, security: SecureRandom): String =
        "${FRAME_PREFIX}s=$sid&i=0&n=1&f=0&d=" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            ByteArray(64).also(security::nextBytes),
        )

    fun parse(text: String): Triple<String, Int, Int>? {
        if (!text.startsWith(FRAME_PREFIX)) return null
        val p = text.removePrefix(FRAME_PREFIX).split('&')
            .mapNotNull {
                val i = it.indexOf('=')
                if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
            }
            .toMap()
        val sid = p["s"] ?: return null
        val i = p["i"]?.toIntOrNull() ?: return null
        val n = p["n"]?.toIntOrNull() ?: return null
        if (n <= 0 || i < 0 || i >= n) return null
        return Triple(sid, i, n)
    }

    fun chunkOf(text: String): String? =
        text.substringAfter("&d=", "").takeIf { it.isNotEmpty() && "&f=1" in text }

    fun isNoise(text: String): Boolean = "&f=0" in text
}

/** 扫描端采集状态机：锁定首个会话、集齐 + 时长门槛（时钟注入，可测）。
 *  锁定语义：先到先锁，异会话帧全部忽略（防污染）；被抢先锁死时调 [reset] 重扫。
 *  假载荷顶替由安全码比对兜底，采集层不做真伪判断。 */
class FrameCollector(private val minCollectMs: Long = FrameCodec.MIN_COLLECT_MS) {
    data class State(
        val collected: Int,
        val total: Int,
        val elapsedMs: Long,
        val complete: Boolean,
        val payload: AddFriendPayload?,
    )

    private val chunks = HashMap<Int, String>()
    var sid: String? = null
        private set
    var total: Int = -1
        private set
    private var firstSeenMs = -1L

    // 完成后只解析一次并缓存实例：快照被 UI 高频轮询（200ms），
    // 反复解析既费电，也会让上游以载荷实例为 key 的
    // remember / LaunchedEffect 每次失效（ByteArray equals 是引用相等）
    private var parsed = false
    private var payload: AddFriendPayload? = null

    fun onFrame(text: String, nowMs: Long): State {
        if (FrameCodec.isNoise(text)) return snapshot(nowMs)
        val frameSid = FrameCodec.parse(text) ?: return snapshot(nowMs)
        if (sid == null) {
            sid = frameSid.first
            total = frameSid.third
            firstSeenMs = nowMs
        }
        if (frameSid.first != sid || frameSid.third != total) return snapshot(nowMs) // 异会话帧
        FrameCodec.chunkOf(text)?.let { chunks[frameSid.second] = it }
        return snapshot(nowMs)
    }

    /** 清空锁定与会话（用户手动「重新扫描」）。 */
    fun reset() {
        chunks.clear()
        sid = null
        total = -1
        firstSeenMs = -1L
        parsed = false
        payload = null
    }

    private fun state(nowMs: Long): State {
        val elapsed = if (firstSeenMs < 0) 0 else (nowMs - firstSeenMs)
        val allCollected = total > 0 && chunks.keys.size >= total
        val enoughTime = elapsed >= minCollectMs
        if (allCollected && enoughTime && !parsed) {
            parsed = true
            payload = (0 until total).mapNotNull { chunks[it] }
                .joinToString("")
                .let { runCatching { AddFriendPayload.parse(String(java.util.Base64.getUrlDecoder().decode(it), Charsets.UTF_8)) }.getOrNull() }
        }
        return State(chunks.keys.size, if (total < 0) 0 else total, elapsed, payload != null, payload)
    }

    /** UI 节拍器调用：无新帧也推进时间窗。 */
    fun snapshot(nowMs: Long): State = state(nowMs)
}
