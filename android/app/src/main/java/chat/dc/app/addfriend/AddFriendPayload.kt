package chat.dc.app.addfriend

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.security.SecureRandom

/** b64url 字母表（数据段 d 的合法字符集；FEC 恢复帧入库前的防御性检查用）。 */
private val B64URL_RE = Regex("[A-Za-z0-9_-]+")

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
 * - [naddr] 出示方 iroh 节点地址快照（dc://node?v=1&…，跨网络直连入口；
 *   节点未就绪时省略——parse 侧可选，旧版载荷缺省为空串）
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
    val naddr: String = "",
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
            "&bucket=${b64(bucket)}&token=${b64(token)}&ble=${b64(ble)}" +
            if (naddr.isEmpty()) "" else "&naddr=${b64(naddr.toByteArray(Charsets.UTF_8))}"
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
            // 可选：iroh 节点地址快照（文本字段经 b64 穿越 URI）
            val naddr = b64(params["naddr"])?.toString(Charsets.UTF_8) ?: ""
            return runCatching { AddFriendPayload(name, id, bundle, bucket, token, ble, naddr) }.getOrNull()
        }
    }
}

object QrCodec {
    /** 生成方形二维码位图。纠错 L（7%）：本场景单帧截屏无意义（须集齐全部
     *  数据帧），用更低的纠错换取更快更稳的解码——「总差最后一帧」的帮凶
     *  之一就是高密度帧 + M 级纠错解码耗时超过展示时长导致跳帧。
     *
     *  位图写入用整块 int[] + [Bitmap.setPixels] 批量填充：逐像素 setPixel
     *  每个点一次 JNI 调用，是编码阶段的大头；批量写入快一个数量级——
     *  这是自适应帧率能把间隔压到视觉下限的前提。 */
    private const val BLACK = 0xFF000000.toInt()
    private const val WHITE = 0xFFFFFFFF.toInt()

    fun encode(content: String, size: Int): Bitmap {
        val matrix = QRCodeWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            size,
            size,
            mapOf(
                EncodeHintType.MARGIN to 1,
                EncodeHintType.ERROR_CORRECTION to com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.L,
            ),
        )
        val w = matrix.width
        val h = matrix.height
        val pixels = IntArray(w * h)
        var idx = 0
        for (y in 0 until h) {
            for (x in 0 until w) {
                pixels[idx++] = if (matrix[x, y]) BLACK else WHITE
            }
        }
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bmp.setPixels(pixels, 0, w, 0, 0, w, h)
        return bmp
    }
}

/**
 * 蓝牙连接帧（f=2）内容：扫码端读到即可发起蓝牙连接的「搭线」信息。
 * - [sid] 所属二维码会话（与数据帧同一 sid = 载荷内容哈希，出示端同轮生成）
 * - [name] 出示方地址名（与载荷 name 同源）
 * - [bleId] 8 字节 BLE 配对 id：出示端已在 PAIR_UUID 广播携带同一 id，扫码端
 *   常驻 BLE 扫描命中即回连——Android 6+ 应用读不到本机蓝牙 MAC 且 BLE 地址
 *   会轮换，动态配对 id 就是本架构里正确的「蓝牙连接信息」
 * - [serviceUuid] 出示端 GATT 服务 UUID（当前实现为 LinkUuids.SERVICE_UUID
 *   常量，帧内携带保持格式自描述）
 * - [challenge] 16 字节当场随机挑战：扫码端回连时原样回传，出示端比对通过才
 *   应答——把 GATT 连接与「当前正在出示的这张动态码」绑定
 */
data class BleConnectInfo(
    val sid: String,
    val name: String,
    val bleId: ByteArray,
    val serviceUuid: String,
    val challenge: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is BleConnectInfo &&
        sid == other.sid && name == other.name && bleId.contentEquals(other.bleId) &&
        serviceUuid == other.serviceUuid && challenge.contentEquals(other.challenge)

    override fun hashCode(): Int = sid.hashCode() * 31 + bleId.contentHashCode()
}

/**
 * 动态分帧二维码（v2 帧格式）：
 * 载荷切成 N 个数据帧循环播放，混入随机噪声帧——单帧/单张截图不含完整信息；
 * 另混入蓝牙连接帧（f=2，[bleFrame]）：设备名 + BLE 配对 id + 服务 UUID + 当场
 * 随机挑战。扫描端读到蓝牙帧即回连（搭线优先，见
 * [FrameCollector.tryBluetoothConnect]），完整身份改经蓝牙上的 Signal 加密通道
 * 交换——二维码只负责搭线。
 *
 * **两阶段出示（蓝牙/身份信息防混暴露）**：f=2 蓝牙帧与 f=1 数据帧绝不在同一
 * 滚动序列出现——阶段 1 只滚 f=2（对方读到即回连，[handshakePass]），蓝牙链路
 * 建立后切阶段 2 只滚 f=1+f=3+f=0（[dataPass]）；蓝牙迟迟未建立（对方不支持
 * 快连/超时）才降级为旧式 f=1/f=2 交替（[dataPass] 带蓝牙帧，安全码比对兜底）。
 * 长曝光单照因此至多捕到一种信息。
 *
 * **每轮刷新（防长曝光拼接）**：每轮展示开始重新生成帧内随机盐（[nonce]），
 * 帧级 CRC 随盐重算——同一张物理二维码每轮在字节层不同；sid 与数据内容不变
 * （sid 绑定的是载荷文本，不是 nonce）。
 *
 * **前向纠错（FEC）**：每 [FEC_GROUP] 个数据帧跟 1 个奇偶校验帧（f=3，
 * [parityFrame]，内容 = 组内数据帧 d 段的 XOR）：丢 1 帧可被扫描端即时恢复
 * （[FrameCollector.tryRecover]），不必等循环重播补齐。扫描端完成门槛 =
 * ≥[MIN_COLLECT_MS] 且（蓝牙帧已扫到 或 数据帧集齐重组成功）；防偷拍时长
 * 门槛不变，出示端同步执行。
 *
 * 帧格式 `dc://addframe?v=2&s=$sid&i=$i&n=$n&f=$f&[x=$nonce&]c=$crc&d=$data`：
 * - [sid] 会话 id = 载荷文本的 SHA-256 截断（64 bit，[payloadTextHash]）。
 *   **绑定内容**：载荷含每场 SecureRandom 的 token/bucket/ble → 每次播放
 *   sid 必然重生成；攻击者既无法预测未开播的 sid，也无法为给定 sid 造出
 *   异内容帧组（哈希原像）——这是对「中途换码」串行攻击的根防线。
 * - [crc] 帧级 CRC32：over `sid|i|n|f|d`（带盐帧 over `sid|i|n|f|x|d`）。
 *   误读/损坏/跨会话拼接帧当场拒收，不入库、等展示端循环重播补齐，不静默收错。
 *   CRC 非密钥校验（防误读不防伪造）——恶意替换内容由重组内容门
 *   （H(重组文本) == sid）兜住。
 * - [x] 帧内随机盐（可选，[NONCE_LEN] hex）：每轮展示重新生成，只进帧包装与
 *   CRC、不进数据段；无 x 段 = 旧式帧（CRC 校验向后兼容）。
 * - 蓝牙连接帧（f=2）无 i/n 段（下标/帧数无意义）：旧版扫描端 parse 失败
 *   自动忽略，向后兼容；奇偶帧（f=3）的 i/n = 组号/组数，旧版扫描端同样
 *   自动忽略。
 */
object FrameCodec {
    const val MIN_COLLECT_MS: Long = 3_000

    /** 锁定后集不齐的自愈时限：超时自动重置允许新会话（防攻击者占锁、
     *  展示方离开、遮挡半途把采集端永久卡死）。 */
    const val LOCK_TIMEOUT_MS: Long = 15_000

    /** 最小视觉间隔：给对面摄像头的最短捕捉时间（zxing 解码一帧也要时间），
     *  帧率再快也不能低于它。 */
    const val MIN_FRAME_INTERVAL_MS: Long = 150

    const val FRAME_PREFIX = "dc://addframe?v=2&"

    /** 帧类型：f=0 噪声 / f=1 数据 / f=2 蓝牙连接（搭线帧，无 i/n 段）/
     *  f=3 奇偶校验（XOR 恢复帧，i/n = 组号/组数）。 */
    const val NOISE_FRAME_TYPE = 0
    const val DATA_FRAME_TYPE = 1
    const val BLE_FRAME_TYPE = 2
    const val PARITY_FRAME_TYPE = 3

    /** FEC 组大小：每 [FEC_GROUP] 个数据帧 1 个奇偶校验帧（组内丢 1 帧可恢复）。 */
    const val FEC_GROUP = 4

    /** 帧内随机盐（nonce）的 hex 长度（32 bit）：每轮展示重新生成。 */
    const val NONCE_LEN = 8

    private const val BLE_DIAL_PREFIX = "dc://bledial?v=1&"

    /** 会话 id（= 载荷哈希截断）的 hex 长度，64 bit。 */
    const val SID_LEN = 16

    // 真实载荷（含 ~1.8KB 的 PreKeyBundle）约 2.6KB；48 字符/帧会切出
    // 50+ 帧（30 秒以上才能集齐），故提到 256：约 11 帧。展示端自适应帧率
    // （见 AdaptiveFramePacer，下限 150ms/帧）、数据:噪声 = 4:1，
    // 全部数据帧 ~2s 一轮，配合 3 秒时长门槛，正常 3-4 秒集齐。
    // 单帧 QR 约 400 字符（版本 13），纠错 L 换取更快解码，可扫。
    const val CHUNK_SIZE = 256

    /** 一帧解析结果（结构 + 校验字段；[crc] 是否有效由 [crcOf] 复核）。
     *  [nonce] 帧内随机盐（无 x 段 = 旧式帧，空串）；[parity] = f=3 奇偶帧
     *  （此时 [index]/[total] = 组号/组数）。 */
    data class Frame(
        val sid: String,
        val index: Int,
        val total: Int,
        val noise: Boolean,
        val crc: String,
        val data: String,
        val nonce: String = "",
        val parity: Boolean = false,
    )

    /** 载荷文本哈希（SHA-256，hex 截断 64 bit）——即会话 id 本身。 */
    fun payloadTextHash(text: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
            .take(SID_LEN)

    /** 会话 id：绑定本次载荷内容（挑战哈希）。 */
    fun sidOf(payload: AddFriendPayload): String = payloadTextHash(payload.encode())

    /** 本轮随机盐（帧内 nonce，hex [NONCE_LEN] = 32 bit）：每轮展示开始时重新
     *  生成——帧级 CRC 随之重算，同一张物理二维码每轮在字节层不同（防长曝光
     *  拼接）；sid 与数据内容不变（sid 绑定的是载荷文本 [payloadTextHash]，
     *  不是 nonce）。 */
    fun nonce(security: SecureRandom): String =
        ByteArray(NONCE_LEN / 2).also(security::nextBytes).joinToString("") { "%02x".format(it) }

    /** 帧级 CRC32（hex 8 位）：over `sid|i|n|f|d`；带盐帧（[nonce] 非空）over
     *  `sid|i|n|f|x|d`，[parity] 时 f 段取 3。字段全参与者可算——定位是
     *  **传输完整性**（误读/截断/拼接即刻显形），不是真实性。 */
    fun crcOf(
        sid: String,
        index: Int,
        total: Int,
        noise: Boolean,
        data: String,
        nonce: String = "",
        parity: Boolean = false,
    ): String {
        val type = when {
            noise -> NOISE_FRAME_TYPE
            parity -> PARITY_FRAME_TYPE
            else -> DATA_FRAME_TYPE
        }
        val core = if (nonce.isEmpty()) "$sid|$index|$total|$type|$data"
        else "$sid|$index|$total|$type|$nonce|$data"
        val crc = java.util.zip.CRC32().apply { update(core.toByteArray(Charsets.UTF_8)) }.value
        return "%08x".format(crc)
    }

    /** 数据/噪声帧文本。[nonce] 非空时帧内携带 `&x=` 盐并参与 CRC：每轮展示用
     *  新盐重建（见 [nonce] 生成器）——sid 与数据内容不变，字节层每轮刷新。 */
    fun buildFrame(sid: String, index: Int, total: Int, noise: Boolean, data: String, nonce: String = ""): String {
        val f = if (noise) NOISE_FRAME_TYPE else DATA_FRAME_TYPE
        val x = if (nonce.isEmpty()) "" else "&x=$nonce"
        return "${FRAME_PREFIX}s=$sid&i=$index&n=$total&f=$f$x" +
            "&c=${crcOf(sid, index, total, noise, data, nonce)}&d=$data"
    }

    /** 载荷文本 → 静态数据段（b64url，按 [CHUNK_SIZE] 切）：帧的「内容」部分，
     *  与每轮随机盐分离——盐只进帧包装与 CRC，不进数据段。 */
    fun segments(payload: AddFriendPayload): List<String> {
        val text = payload.encode()
        val n = (text.length + CHUNK_SIZE - 1) / CHUNK_SIZE
        return (0 until n).map { i ->
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                text.substring(i * CHUNK_SIZE, minOf((i + 1) * CHUNK_SIZE, text.length)).toByteArray(Charsets.UTF_8),
            )
        }
    }

    /** 数据帧组（无盐旧式帧；新式带盐的一轮展示序列见 [dataPass]）。 */
    fun split(payload: AddFriendPayload): List<String> {
        val sid = payloadTextHash(payload.encode())
        val segs = segments(payload)
        return segs.mapIndexed { i, d -> buildFrame(sid, i, segs.size, noise = false, data = d) }
    }

    /** 噪声帧：随机内容、f=0，扫描端必须忽略——让单帧截屏失去意义。 */
    fun noiseFrame(sid: String, security: SecureRandom): String =
        buildFrame(
            sid, 0, 1, noise = true,
            data = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(ByteArray(64).also(security::nextBytes)),
        )

    // ---------------- 前向纠错（f=3 奇偶帧）与两阶段展示序列 ----------------

    /** 奇偶校验段（f=3 帧内容）：组内各数据帧 d 段（b64url 文本的 US-ASCII
     *  字节）按组内最长长度零填充对齐后逐字节 XOR，再 b64url。零填充无歧义——
     *  b64url 字母表不含 0x00，恢复侧去尾零即还原原文。 */
    fun parityOf(segments: List<String>): String {
        require(segments.isNotEmpty()) { "parity over empty group" }
        val acc = ByteArray(segments.maxOf { it.length })
        for (s in segments) {
            val b = s.toByteArray(Charsets.US_ASCII)
            for (i in b.indices) acc[i] = (acc[i].toInt() xor b[i].toInt()).toByte()
        }
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(acc)
    }

    /** FEC 组数：每 [FEC_GROUP] 个数据帧 1 个奇偶校验帧。 */
    fun fecGroupCount(total: Int): Int = (total + FEC_GROUP - 1) / FEC_GROUP

    /** FEC 组 [g] 覆盖的数据帧下标（末组可短于 [FEC_GROUP]）。 */
    fun fecGroupIndices(total: Int, g: Int): List<Int> {
        val from = g * FEC_GROUP
        return (from until minOf(from + FEC_GROUP, total)).toList()
    }

    /** 奇偶校验帧（f=3）：`…&i=$组号&n=$组数&f=3&[x=$nonce&]c=$crc&d=$奇偶段`。
     *  扫描端组内恰缺 1 帧时用同组奇偶帧 XOR 即时恢复，不必等循环重播；
     *  旧版扫描端 parse 不认 f=3 自动忽略，也不占数据帧位。 */
    fun parityFrame(sid: String, group: Int, groups: Int, parity: String, nonce: String = ""): String {
        val x = if (nonce.isEmpty()) "" else "&x=$nonce"
        return "${FRAME_PREFIX}s=$sid&i=$group&n=$groups&f=$PARITY_FRAME_TYPE$x" +
            "&c=${crcOf(sid, group, groups, noise = false, data = parity, nonce = nonce, parity = true)}&d=$parity"
    }

    /** 阶段 1（蓝牙搭线）一轮序列：只滚 f=2 蓝牙帧（少量重复——对方读到即
     *  回连），本阶段不出示任何数据帧。 */
    fun handshakePass(bleInfo: BleConnectInfo, nonce: String, repeats: Int = 3): List<String> =
        List(repeats) { bleFrame(bleInfo, nonce) }

    /** 数据阶段一轮序列（阶段 2 身份交换 / 降级模式共用，纯 JVM 可测）：
     *  - [bleInfo] == null（阶段 2）：只滚 f=1 数据帧 + f=3 奇偶帧 + f=0 噪声帧。
     *    f=2 蓝牙帧与 f=1 数据帧绝不在同一滚动序列出现——长曝光单照至多捕到一种；
     *  - [bleInfo] != null（降级模式）：旧式 f=1/f=2 每 2 帧交替（对端不支持蓝牙
     *    快连的回退路径，安全码比对兜底）+ 奇偶帧 + 噪声帧。
     *  奇偶帧跟在每个 FEC 组末尾（[FEC_GROUP] 个数据帧 1 个，末组可短）；
     *  噪声帧每 4 个数据帧 1 个（防单帧截屏）。全部帧用本轮 [nonce] 重建
     *  （CRC 随之重算）：sid/数据不变，字节层每轮刷新；噪声帧当场随机。 */
    fun dataPass(
        sid: String,
        segments: List<String>,
        bleInfo: BleConnectInfo?,
        nonce: String,
        security: SecureRandom,
    ): List<String> = buildList {
        val total = segments.size
        val groups = fecGroupCount(total)
        val parityDs = (0 until groups).map { g -> parityOf(fecGroupIndices(total, g).map { segments[it] }) }
        segments.forEachIndexed { i, d ->
            add(buildFrame(sid, i, total, noise = false, data = d, nonce = nonce))
            if (bleInfo != null && i % 2 == 1) add(bleFrame(bleInfo, nonce))
            if (i > 0 && i % 4 == 0) add(noiseFrame(sid, security))
            if ((i + 1) % FEC_GROUP == 0 || i == total - 1) {
                add(parityFrame(sid, i / FEC_GROUP, groups, parityDs[i / FEC_GROUP], nonce))
            }
        }
    }

    /** 蓝牙连接帧（f=2）帧级 CRC（over `sid|ble|f|d`；带盐帧 over
     *  `sid|ble|f|x|d`；index/total 无意义不参与）。 */
    private fun bleCrc(sid: String, data: String, nonce: String = ""): String {
        val core = if (nonce.isEmpty()) "$sid|ble|$BLE_FRAME_TYPE|$data"
        else "$sid|ble|$BLE_FRAME_TYPE|$nonce|$data"
        val crc = java.util.zip.CRC32().apply { update(core.toByteArray(Charsets.UTF_8)) }.value
        return "%08x".format(crc)
    }

    /** 蓝牙连接帧：`dc://addframe?v=2&s=$sid&f=2&[x=$nonce&]c=$crc&d=$data`，
     *  d = b64url(`dc://bledial?v=1&n=名&b=配对id&u=服务UUID&c=挑战`)。
     *  [nonce] 非空 = 每轮刷新的字节层（防长曝光拼接）。
     *  无 i/n 段 → 旧版扫描端 [parse] 解析失败自动忽略；f=2 也不占数据帧位。 */
    fun bleFrame(info: BleConnectInfo, nonce: String = ""): String {
        val b64 = { bytes: ByteArray ->
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }
        val body = "${BLE_DIAL_PREFIX}n=${info.name}&b=${b64(info.bleId)}" +
            "&u=${info.serviceUuid}&c=${b64(info.challenge)}"
        val d = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(body.toByteArray(Charsets.UTF_8))
        val x = if (nonce.isEmpty()) "" else "&x=$nonce"
        return "${FRAME_PREFIX}s=${info.sid}&f=$BLE_FRAME_TYPE$x&c=${bleCrc(info.sid, d, nonce)}&d=$d"
    }

    /** 蓝牙连接帧 → 搭线信息。数据帧/噪声帧/非协议文本一律返回 null；
     *  帧级 CRC（[bleCrc]）不符同样拒绝。 */
    fun parseBleFrame(text: String): BleConnectInfo? {
        if (!text.startsWith(FRAME_PREFIX)) return null
        val p = text.removePrefix(FRAME_PREFIX).split('&')
            .mapNotNull {
                val i = it.indexOf('=')
                if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
            }
            .toMap()
        if (p["f"]?.toIntOrNull() != BLE_FRAME_TYPE) return null
        val sid = p["s"]?.takeIf { it.length == SID_LEN } ?: return null
        val c = p["c"]?.takeIf { it.length == 8 } ?: return null
        val d = p["d"]?.takeIf { it.isNotEmpty() } ?: return null
        // 帧内随机盐可选（无 x 段 = 旧式帧）；盐参与帧级 CRC
        val nonce = p["x"] ?: ""
        if (bleCrc(sid, d, nonce) != c) return null
        val body = runCatching {
            String(java.util.Base64.getUrlDecoder().decode(d), Charsets.UTF_8)
        }.getOrNull() ?: return null
        if (!body.startsWith(BLE_DIAL_PREFIX)) return null
        val q = body.removePrefix(BLE_DIAL_PREFIX).split('&')
            .mapNotNull {
                val i = it.indexOf('=')
                if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
            }
            .toMap()
        val name = q["n"]?.takeIf { chat.dc.app.core.SignalCore.NAME_RE.matches(it) } ?: return null
        val b64d = { s: String? ->
            s?.let { runCatching { java.util.Base64.getUrlDecoder().decode(it) }.getOrNull() }
        }
        val bleId = b64d(q["b"])?.takeIf { it.size == 8 } ?: return null
        val challenge = b64d(q["c"])?.takeIf { it.size == 16 } ?: return null
        val uuid = q["u"]?.takeIf { runCatching { java.util.UUID.fromString(it) }.isSuccess } ?: return null
        return BleConnectInfo(sid, name, bleId, uuid, challenge)
    }

    fun parse(text: String): Frame? {
        if (!text.startsWith(FRAME_PREFIX)) return null
        val p = text.removePrefix(FRAME_PREFIX).split('&')
            .mapNotNull {
                val i = it.indexOf('=')
                if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
            }
            .toMap()
        val sid = p["s"]?.takeIf { it.length == SID_LEN } ?: return null
        val i = p["i"]?.toIntOrNull() ?: return null
        val n = p["n"]?.toIntOrNull() ?: return null
        if (n <= 0 || i < 0 || i >= n) return null
        val f = p["f"] ?: return null
        if (f != "0" && f != "1" && f != "3") return null
        // 帧级校验字段必须在场：旧 v1 无 c 帧、缺 c 帧一律拒收
        val c = p["c"]?.takeIf { it.length == 8 } ?: return null
        // 帧内随机盐（x 段）可选：无盐 = 旧式帧（CRC 校验向后兼容）；
        // f=3 奇偶帧的 i/n = 组号/组数
        return Frame(
            sid, i, n,
            noise = f == "0",
            crc = c,
            data = p["d"] ?: "",
            nonce = p["x"] ?: "",
            parity = f == "3",
        )
    }

    /** 解析 + 帧级校验一步到位：CRC 不符返回 null（采集端视为坏帧）。 */
    fun verify(text: String): Frame? =
        parse(text)?.takeIf {
            crcOf(it.sid, it.index, it.total, it.noise, it.data, it.nonce, it.parity) == it.crc
        }
}

/**
 * 自适应帧率节拍器（纯 JVM 可测）：
 * 实测 QR 编码耗时（zxing 矩阵 + 位图写入，CPU 密集）→ EWMA 平滑 →
 * 帧间隔 = max(EWMA, [minVisualMs] 最小视觉间隔)。
 * 机器越好编码越快，间隔自动贴近视觉下限跑满设备能力；慢设备自动拉长，
 * 不再是拍脑袋固定值，也不会因编码超时造成帧积压。EWMA（α=0.3）只为
 * 抹平 GC/调度抖动，不改变「跟随实测」的本意。
 */
class AdaptiveFramePacer(
    private val minVisualMs: Long = FrameCodec.MIN_FRAME_INTERVAL_MS,
    private val alpha: Double = 0.3,
) {
    private var emaMs = Double.NaN

    /** 编码完一帧后调用：记录耗时，返回距下一帧应等待的毫秒数。 */
    fun afterEncode(encodeMs: Long): Long {
        val e = encodeMs.coerceAtLeast(0).toDouble()
        emaMs = if (emaMs.isNaN()) e else alpha * e + (1 - alpha) * emaMs
        return intervalMs()
    }

    /** 当前建议间隔 = max(EWMA(实测编码耗时), 最小视觉间隔)。 */
    fun intervalMs(): Long =
        maxOf(minVisualMs, if (emaMs.isNaN()) 0L else kotlin.math.ceil(emaMs).toLong())
}

/** 扫描端采集状态机（纯 JVM，时钟注入可测）。锁定与校验语义：
 *  - **首帧锁定**：首个通过帧级校验的数据帧锁定（sid, 总帧数），先到先锁，
 *    异会话帧全部忽略（防污染）；噪声帧/非协议文本一律忽略。
 *  - **帧级 CRC**：坏帧拒收入库（[State.rejected] 计数），等展示端循环
 *    重播补齐——丢帧/误读可检测、可恢复，不静默收错。
 *  - **前向纠错（FEC）**：奇偶校验帧（f=3，内容 = 每 [FrameCodec.FEC_GROUP] 个
 *    数据帧的 XOR）不锁定会话、不占数据帧位；组内恰缺 1 帧且奇偶帧在场 →
 *    XOR 即时恢复（[State.recovered] 计数），缺 ≥2 帧等循环重播再触发。
 *  - **内容门**：重组文本哈希必须等于锁定的 sid（sid=内容哈希，见
 *    [FrameCodec.sidOf]）。同 sid 异内容的顶替帧（攻击者可自行重算 CRC）
 *    在这里显形；门不过**不清锁**——展示端循环重播会以真帧逐槽覆盖，
 *    下一次校验自然通过，避免攻击者用 reset 打断合法采集。
 *  - **蓝牙帧先到先锁**：蓝牙连接帧（f=2）与数据会话锁相互独立，首个
 *    有效蓝牙帧经 [tryBluetoothConnect] 立即回调搭线信息（不等数据帧
 *    集齐）；异会话蓝牙帧忽略。
 *  - **锁超时自愈**：锁定后 [lockTimeoutMs] 内没集齐 → 自动重置允许新会话。
 *  - **≥[minCollectMs] 时长门槛**（防偷拍）不变：完成 = 时长到且（蓝牙帧
 *    在手 或 数据帧集齐重组成功）。
 *  假载荷顶替最终由安全码比对兜底，采集层只做完整性/绑定校验。 */
class FrameCollector(
    private val minCollectMs: Long = FrameCodec.MIN_COLLECT_MS,
    private val lockTimeoutMs: Long = FrameCodec.LOCK_TIMEOUT_MS,
) {
    data class State(
        val collected: Int,
        val total: Int,
        val elapsedMs: Long,
        val complete: Boolean,
        val payload: AddFriendPayload?,
        /** 缺失帧下标（升序，0 基）。UI 显示「等待帧 x/y」；展示端循环多播自动补齐。 */
        val missing: List<Int>,
        /** 被拒绝帧的累计数：CRC 失败 / 异会话 / 内容门不符（诊断与测试用）。 */
        val rejected: Int,
        /** 由奇偶校验帧（f=3）XOR 恢复的数据帧累计数（FEC 生效次数）。 */
        val recovered: Int,
        /** 已扫到的蓝牙连接帧（f=2）搭线信息；null = 尚未扫到。 */
        val ble: BleConnectInfo? = null,
    )

    private val chunks = HashMap<Int, String>()
    /** FEC 奇偶帧（f=3）入库：组号 → 奇偶段（b64url）。不占数据帧位、不参与锁定。 */
    private val parityChunks = HashMap<Int, String>()
    var sid: String? = null
        private set
    var total: Int = -1
        private set
    private var firstSeenMs = -1L
    private var ble: BleConnectInfo? = null
    private var bleSid: String? = null

    // 完成后只解析一次并缓存实例：快照被 UI 高频轮询（200ms），
    // 反复解析既费电，也会让上游以载荷实例为 key 的
    // remember / LaunchedEffect 每次失效（ByteArray equals 是引用相等）
    private var parsed = false
    private var payload: AddFriendPayload? = null
    private var gateFailed = false
    private var rejectedCount = 0
    private var recoveredCount = 0

    fun onFrame(text: String, nowMs: Long): State {
        // 锁死超时自愈：锁定后一直集不齐（被异会话占锁/展示方离开/遮挡），
        // 自动重置允许新会话——已完成（payload != null）则不打扰
        if (sid != null && payload == null && nowMs - firstSeenMs > lockTimeoutMs) reset()
        // 蓝牙连接帧（f=2）：锁定并记录搭线信息，不占数据帧位、不影响数据会话锁
        FrameCodec.parseBleFrame(text)?.let {
            lockBle(it, nowMs)
            return snapshot(nowMs)
        }
        val f = FrameCodec.parse(text)
        if (f == null) {
            // 非协议文本静默忽略；长得像协议帧但结构非法（缺 c 等）计入拒绝
            if (text.startsWith(FrameCodec.FRAME_PREFIX)) rejectedCount++
            return snapshot(nowMs)
        }
        if (f.noise) return snapshot(nowMs)
        if (FrameCodec.crcOf(f.sid, f.index, f.total, f.noise, f.data, f.nonce, f.parity) != f.crc) {
            rejectedCount++ // 坏帧/拼接帧：不入库，等展示端循环重播
            return snapshot(nowMs)
        }
        if (f.parity) {
            // 奇偶校验帧（f=3）：不锁定会话（n 段是组数不是数据帧数，锁定会错绑
            // 总数）、不占数据帧位；锁定后异会话/组数不符拒收，同会话入库并尝试
            // XOR 恢复缺失帧
            val locked = sid
            when {
                locked == null -> Unit // 未锁定：忽略（奇偶帧不参与首帧锁定）
                f.sid != locked || f.total != FrameCodec.fecGroupCount(total) -> rejectedCount++
                else -> {
                    parityChunks[f.index] = f.data
                    tryRecover()
                }
            }
            return snapshot(nowMs)
        }
        if (sid == null) {
            sid = f.sid
            total = f.total
            // 时长门槛锚定首帧（数据或蓝牙帧，先到先锚）——门槛到期时刻在
            // 数据/蓝牙两条路径间保持同一时钟，不因数据锁后到而漂移
            if (firstSeenMs < 0) firstSeenMs = nowMs
        }
        if (f.sid != sid || f.total != total) {
            rejectedCount++ // 异会话帧
            return snapshot(nowMs)
        }
        chunks[f.index] = f.data
        tryRecover() // 新帧可能补齐某组「只差 1 帧」的恢复条件
        return snapshot(nowMs)
    }

    /** 前向纠错：组内奇偶帧在场且恰缺 1 帧 → XOR 即时恢复（入参都过了帧级
     *  CRC；恢复结果还须是合法 b64url 段，并最终过重组内容门兜底）。
     *  缺 ≥2 帧不动作——单奇偶只能救 1 帧，等展示端循环重播补齐后再触发。 */
    private fun tryRecover() {
        val t = total
        if (t <= 0) return
        for (g in 0 until FrameCodec.fecGroupCount(t)) {
            val parity = parityChunks[g] ?: continue
            val group = FrameCodec.fecGroupIndices(t, g)
            val missing = group.filter { it !in chunks.keys }
            if (missing.size != 1) continue
            val known = group.filter { it != missing[0] }.mapNotNull { chunks[it] }
            if (known.size != group.size - 1) continue
            val parityRaw = runCatching { java.util.Base64.getUrlDecoder().decode(parity) }.getOrNull() ?: continue
            val acc = parityRaw.copyOf()
            var fits = true
            for (s in known) {
                val b = s.toByteArray(Charsets.US_ASCII)
                if (b.size > acc.size) { fits = false; break } // 与奇偶帧不同源：弃用等重播
                for (i in b.indices) acc[i] = (acc[i].toInt() xor b[i].toInt()).toByte()
            }
            if (!fits) continue
            var end = acc.size
            while (end > 0 && acc[end - 1] == 0.toByte()) end-- // b64url 无 0x00：尾零即填充
            val recovered = String(acc, 0, end, Charsets.US_ASCII)
            if (recovered.isNotEmpty() && B64URL_RE.matches(recovered)) {
                chunks[missing[0]] = recovered
                recoveredCount++
            }
        }
    }

    /** 读到蓝牙连接帧（f=2）立即回调 [onConnect]（搭线优先，不等数据帧集齐）。
     *  回调第二参 = 时长门槛到期时刻（锚定首帧，与完成门槛同钟同阈）——到点前
     *  蓝牙通道只搭线不交换完整身份，防偷拍时长门槛由双端共同执行。
     *  返回该帧是否为本会话有效蓝牙帧；重复帧不重复回调，异会话蓝牙帧拒绝。 */
    fun tryBluetoothConnect(frame: String, nowMs: Long, onConnect: (BleConnectInfo, Long) -> Unit): Boolean {
        val info = FrameCodec.parseBleFrame(frame) ?: return false
        val locked = bleSid
        if (locked != null && locked != info.sid) return false
        val first = ble == null
        lockBle(info, nowMs)
        if (first) onConnect(info, firstSeenMs + minCollectMs)
        return true
    }

    /** 蓝牙帧先到先锁（与数据会话锁独立）；重复帧幂等、异会话帧忽略。
     *  首帧（数据或蓝牙）同时起算时长门槛。 */
    private fun lockBle(info: BleConnectInfo, nowMs: Long) {
        val locked = bleSid
        if (locked != null && locked != info.sid) return
        if (ble == null) {
            ble = info
            bleSid = info.sid
            if (firstSeenMs < 0) firstSeenMs = nowMs
        }
    }

    /** 清空锁定与会话（用户手动「重新扫描」；统计 [State.rejected]/
     *  [State.recovered] 保留累计）。 */
    fun reset() {
        chunks.clear()
        parityChunks.clear()
        sid = null
        total = -1
        firstSeenMs = -1L
        parsed = false
        payload = null
        gateFailed = false
        ble = null
        bleSid = null
    }

    private fun state(nowMs: Long): State {
        val elapsed = if (firstSeenMs < 0) 0 else (nowMs - firstSeenMs)
        val allCollected = total > 0 && chunks.keys.size >= total
        val enoughTime = elapsed >= minCollectMs
        if (allCollected && enoughTime && !parsed) {
            // 各帧 d 段是独立 b64 编码（段长非 3 倍数时填充位错位），
            // 必须逐段 decode 后再拼接原文，不能整串 decode
            val text = (0 until total).mapNotNull { chunks[it] }
                .mapNotNull { seg ->
                    runCatching { String(java.util.Base64.getUrlDecoder().decode(seg), Charsets.UTF_8) }.getOrNull()
                }
                .joinToString("")
            // 内容门：sid = 载荷文本哈希。被顶替/拼接的重组结果过不了门
            // （为给定 sid 造异内容 = 哈希原像）；门不过不清锁，等真帧覆盖
            val p = text.takeIf { FrameCodec.payloadTextHash(it) == sid }
                ?.let { runCatching { AddFriendPayload.parse(it) }.getOrNull() }
            if (p != null) {
                parsed = true
                gateFailed = false
                payload = p
            } else if (!gateFailed) {
                gateFailed = true
                rejectedCount++
            }
        }
        // 完成门槛（SP-3 时长防偷拍不变）：≥3 秒 且（蓝牙帧已扫到 或 数据帧
        // 集齐重组成功）。蓝牙帧在手即完成采集阶段——完整身份改经蓝牙加密
        // 通道交换；数据帧集齐保留为旧版对端回退路径。
        val complete = enoughTime && (ble != null || payload != null)
        return State(
            collected = chunks.keys.size,
            total = if (total < 0) 0 else total,
            elapsedMs = elapsed,
            complete = complete,
            payload = payload,
            missing = if (total <= 0) emptyList() else (0 until total).filter { it !in chunks.keys },
            rejected = rejectedCount,
            recovered = recoveredCount,
            ble = ble,
        )
    }

    /** UI 节拍器调用：无新帧也推进时间窗。 */
    fun snapshot(nowMs: Long): State = state(nowMs)
}
