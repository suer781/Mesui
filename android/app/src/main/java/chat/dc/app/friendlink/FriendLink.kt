package chat.dc.app.friendlink

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 好友回连匹配层：常驻 BLE 广播不携带任何稳定身份，扫端本地派生候选 ID
 * 查布隆过滤器，命中才回连，回连后 HMAC 挑战应答定身份——匹配先于连接，
 * 假阳性与过滤器冒充都被 HMAC 层挡掉。
 *
 * 派生链（每位好友一个配对时交换的共享秘密 S_i，contacts.link_secret）：
 *   K_{i,d}    = HKDF-SHA256(ikm=S_i, info="dc-link-day-v1"||d)        每日轮换
 *   ID_{i,d,t} = HKDF-SHA256(ikm=K, info="dc-link-slot-v1"||t) 前 4 字节  10 分钟槽位
 *   广播负载    = [版本 1B][Bloom(所有好友当前槽位 ID)+随机填充 128B]
 * 参数：1024 bit / 7 哈希 / 填充到固定 set-bit 上限（100 好友当量），
 * 不泄露真实好友数。跨日不可关联由每日密钥切断；物理持续跟随者的
 * 槽位边界连续性属无线电物理限制，威胁模型如实接受。
 *
 * 本文件为纯 JVM 逻辑（javax.crypto），可单测；两端算法一致即可。
 */
object FriendLink {
    const val SLOT_MS = 600_000L          // 10 分钟
    const val SLOTS_PER_DAY = 144
    const val BLOOM_BITS = 1024
    const val BLOOM_BYTES = BLOOM_BITS / 8
    const val HASHES = 7
    const val CAP_FRIENDS = 100           // set-bit 目标 = HASHES*CAP，不足用随机填充凑
    const val ID_LEN = 4
    const val PAYLOAD_VERSION: Byte = 1
    const val HMAC_TRUNC = 16             // 挑战应答截断长度

    fun currentSlot(nowMs: Long = System.currentTimeMillis()): Long = nowMs / SLOT_MS

    private fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    /** HKDF-SHA256（extract+expand），输出 len 字节。 */
    private fun hkdf(ikm: ByteArray, info: ByteArray, len: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // 固定空盐语境：salt=SHA256("dc-friendlink-salt")，链参数全项目一致
        val salt = sha256("dc-friendlink-salt".toByteArray(Charsets.UTF_8))
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val out = ByteArray(len)
        var prev = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < len) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            prev = mac.doFinal(prev + info + byteOf(counter))
            val take = minOf(prev.size, len - written)
            prev.copyInto(out, written, 0, take)
            written += take
            counter++
        }
        return out
    }

    private fun byteOf(v: Int): ByteArray = byteArrayOf(v.toByte())

    private fun le8(v: Long): ByteArray =
        ByteArray(8) { i -> (v ushr (8 * i)).toByte() }

    /** 某好友在槽位 t 的 4 字节派生 ID。 */
    fun slotId(secret: ByteArray, slot: Long): ByteArray {
        val day = slot / SLOTS_PER_DAY
        val dayKey = hkdf(secret, "dc-link-day-v1".toByteArray(Charsets.UTF_8) + le8(day), 32)
        return hkdf(dayKey, "dc-link-slot-v1".toByteArray(Charsets.UTF_8) + le8(slot), ID_LEN)
    }

    /** ID → HASHES 个 bloom 位下标（j 混入域分隔，视作独立哈希）。 */
    private fun bitIndices(id: ByteArray): IntArray {
        val idx = IntArray(HASHES)
        for (j in 0 until HASHES) {
            val h = sha256(id + j.toByte())
            val v = ((h[0].toInt() and 0xFF) shl 16) or
                ((h[1].toInt() and 0xFF) shl 8) or
                (h[2].toInt() and 0xFF)
            idx[j] = v % BLOOM_BITS
        }
        return idx
    }

    /** 当前槽位广播过滤器：真实好友 ID 置位 + 随机填充到固定 set-bit 目标。
     *  padRnd 为当槽 CSPRNG 随机字节（建议 ≥2048B，供填充迭代取用）。 */
    fun buildBloom(secrets: List<ByteArray>, slot: Long, padRnd: ByteArray): ByteArray {
        require(secrets.size <= CAP_FRIENDS) { "超过过滤器容量当量: ${secrets.size}" }
        val bits = BooleanArray(BLOOM_BITS)
        fun add(id: ByteArray) = bitIndices(id).forEach { bits[it] = true }
        secrets.forEach { add(slotId(it, slot)) }
        val target = HASHES * CAP_FRIENDS
        var off = 0
        while (bits.count { it } < target && off + ID_LEN <= padRnd.size) {
            add(padRnd.copyOfRange(off, off + ID_LEN))
            off += ID_LEN
        }
        val out = ByteArray(BLOOM_BYTES)
        for (i in 0 until BLOOM_BITS) {
            if (bits[i]) out[i / 8] = (out[i / 8].toInt() or (1 shl (i % 8))).toByte()
        }
        return out
    }

    /** 扫描端：过滤器是否可能包含该 ID（7 位全置）。 */
    fun bloomHit(bloom: ByteArray, id: ByteArray): Boolean =
        bitIndices(id).all { (bloom[it / 8].toInt() shr (it % 8)) and 1 == 1 }

    /**
     * 扫描端候选：对每个好友用 当前槽+前一槽 两个容忍窗口查 bloom
     * （槽边界时钟偏差容忍），返回命中的好友下标与其命中 ID。
     * 假阳性交给回连后的 HMAC 挑战应答过滤。
     */
    fun candidates(bloom: ByteArray, secrets: List<ByteArray>, slot: Long): List<Pair<Int, ByteArray>> =
        secrets.mapIndexed { i, s ->
            listOf(slotId(s, slot), slotId(s, slot - 1)).firstOrNull { bloomHit(bloom, it) }?.let { i to it }
        }.filterNotNull()

    /** 挑战应答 HMAC：截断 16 字节。 */
    fun hmac(secret: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(secret, "HmacSHA256"))
            doFinal(data).copyOf(HMAC_TRUNC)
        }

    /** 广播 serviceData 负载组装：版本+过滤器。 */
    fun advertisePayload(bloom: ByteArray): ByteArray = byteArrayOf(PAYLOAD_VERSION) + bloom

    /** 解析广播负载；版本不符/长度不对返回 null。 */
    fun parseAdvertisePayload(data: ByteArray?): ByteArray? {
        if (data == null || data.size != 1 + BLOOM_BYTES) return null
        if (data[0] != PAYLOAD_VERSION) return null
        return data.copyOfRange(1, data.size)
    }
}
