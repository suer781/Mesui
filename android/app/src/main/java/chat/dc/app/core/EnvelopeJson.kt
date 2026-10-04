package chat.dc.app.core

/**
 * Envelope 的 serde_json 兼容编解码（仅投递队列所需字段）。
 *
 * Rust 侧 `crates/core/src/envelope.rs` 的 `Envelope` 经 serde_json 序列化，
 * 字段顺序固定：`msg_id, sender, recipient, group, kind, body, sent_at_ms,
 * ttl_hops, sig(可选)`；`kind` 为枚举名（"Text" 等），`sig` 为 None 时整段省略。
 *
 * 本工具在 Kotlin 侧构造/解析同一格式，避免依赖 org.json（纯 JVM 单测不可用）
 * 或为投递队列新增 FFI 出口。解析只取发送回调需要的字段。
 */
object EnvelopeJson {

    /** 解析后的信封（只保留投递回调需要的字段）。 */
    data class ParsedEnvelope(
        val msgId: ByteArray,
        /** 32 字节收件方标识；null = 群播/中继信封（本应用不投递）。 */
        val recipient: ByteArray?,
        /** 密文体（Signal WireMessage 的 msgType + ciphertext）。 */
        val body: ByteArray,
        val sentAtMs: Long,
    )

    /**
     * 构造 Text 类型信封的 serde_json 字符串。
     *
     * @param sender 32 字节发送方 NodeId（本端 iroh 节点 id 或零占位；仅存档用，
     *   本应用的 BLE/iroh 发送通道不把信封本身发到线上，只取 body）。
     * @param recipient 32 字节收件方标识（联系人 Signal identity 去掉 libsignal
     *   类型前缀后的 32 字节——信封仅存本地，此字段是投递回调反查联系人的内部键）。
     */
    fun buildText(
        msgId: ByteArray,
        sender: ByteArray,
        recipient: ByteArray,
        body: ByteArray,
        sentAtMs: Long,
        ttlHops: Int = 6,
    ): String {
        require(msgId.size == 16) { "msg_id 必须 16 字节" }
        require(sender.size == 32) { "sender 必须 32 字节" }
        require(recipient.size == 32) { "recipient 必须 32 字节" }
        val sb = StringBuilder(160 + body.size * 2)
        sb.append("{\"msg_id\":").append(bytesToJson(msgId))
        sb.append(",\"sender\":").append(bytesToJson(sender))
        sb.append(",\"recipient\":").append(bytesToJson(recipient))
        sb.append(",\"group\":null")
        sb.append(",\"kind\":\"Text\"")
        sb.append(",\"body\":").append(bytesToJson(body))
        sb.append(",\"sent_at_ms\":").append(sentAtMs)
        sb.append(",\"ttl_hops\":").append(ttlHops)
        sb.append('}')
        return sb.toString()
    }

    /** 解析 Envelope JSON；格式非法或关键字段缺失返回 null。 */
    @Suppress("UNCHECKED_CAST")
    fun parse(json: String): ParsedEnvelope? {
        // 解析器对畸形输入抛 IllegalArgumentException；回调路径必须容错 → 一律返回 null
        val obj = runCatching { JsonParser.parseObject(json) }.getOrNull() ?: return null
        val msgId = (obj["msg_id"] as? List<Long>)?.toByteArrayOrNull(16) ?: return null
        // recipient 允许 null（群播/中继信封）；若出现数组则必须 32 字节，否则视为畸形
        val recipient = when (val raw = obj["recipient"]) {
            null -> null
            is List<*> -> (raw as? List<Long>)?.toByteArrayOrNull(32) ?: return null
            else -> return null
        }
        val body = (obj["body"] as? List<Long>)?.toByteArrayOrNull() ?: return null
        val sentAtMs = obj["sent_at_ms"] as? Long ?: 0L
        return ParsedEnvelope(msgId, recipient, body, sentAtMs)
    }

    private fun bytesToJson(bytes: ByteArray): String {
        val sb = StringBuilder(2 + bytes.size * 2)
        sb.append('[')
        for ((i, b) in bytes.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append(b.toInt() and 0xFF)
        }
        sb.append(']')
        return sb.toString()
    }

    private fun List<Long>.toByteArrayOrNull(expected: Int? = null): ByteArray? {
        if (expected != null && size != expected) return null
        return ByteArray(size) { this[it].toInt().toByte() }
    }
}

/** 极简 JSON 解析器：只覆盖 Envelope 的 serde_json 形状（对象 + 数字数组 + null）。 */
private object JsonParser {
    fun parseObject(json: String): Map<String, Any?>? {
        val p = Parser(json)
        val v = p.parseValue() ?: return null
        return v as? Map<String, Any?>
    }
}

private class Parser(private val s: String) {
    private var i = 0

    fun parseValue(): Any? {
        skipWs()
        if (i >= s.length) return null
        return when (s[i]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> { expect("true"); true }
            'f' -> { expect("false"); false }
            'n' -> { expect("null"); null }
            else -> parseNumber()
        }
    }

    private fun parseObject(): Map<String, Any?> {
        i++ // {
        val map = LinkedHashMap<String, Any?>()
        skipWs()
        if (i < s.length && s[i] == '}') { i++; return map }
        while (true) {
            skipWs()
            val key = parseString()
            skipWs()
            expect(":")
            val value = parseValue()
            map[key] = value
            skipWs()
            if (i >= s.length) return map
            when (s[i]) {
                ',' -> { i++; continue }
                '}' -> { i++; return map }
                else -> return map
            }
        }
    }

    private fun parseArray(): List<Long> {
        i++ // [
        val list = ArrayList<Long>()
        skipWs()
        if (i < s.length && s[i] == ']') { i++; return list }
        while (true) {
            skipWs()
            list.add(parseNumber())
            skipWs()
            if (i >= s.length) return list
            when (s[i]) {
                ',' -> { i++; continue }
                ']' -> { i++; return list }
                else -> return list
            }
        }
    }

    private fun parseString(): String {
        i++ // "
        val sb = StringBuilder()
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> { i++; return sb.toString() }
                c == '\\' && i + 1 < s.length -> {
                    i++
                    when (val e = s[i]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i + 1, (i + 5).coerceAtMost(s.length))
                            sb.append(hex.toIntOrNull(16)?.toChar() ?: '?')
                            i += 4
                        }
                        else -> sb.append(e)
                    }
                    i++
                }
                else -> { sb.append(c); i++ }
            }
        }
        return sb.toString()
    }

    private fun parseNumber(): Long {
        skipWs()
        val start = i
        if (i < s.length && s[i] == '-') i++
        while (i < s.length && s[i].isDigit()) i++
        return s.substring(start, i).toLongOrNull() ?: 0L
    }

    private fun skipWs() {
        while (i < s.length && s[i].isWhitespace()) i++
    }

    private fun expect(tok: String) {
        if (!s.startsWith(tok, i)) throw IllegalArgumentException("JSON 非法 @$i")
        i += tok.length
    }
}