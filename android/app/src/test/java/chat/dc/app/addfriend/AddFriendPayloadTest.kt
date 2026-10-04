package chat.dc.app.addfriend

import chat.dc.app.ble.parseDcs1
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.SecureRandom

/**
 * P0 修复回归：QR 载荷携带真实 iroh 节点地址（naddr 编码/解析往返），
 * 以及 DCS1 密文里追加 host naddr 的握手载荷双向解析（旧版/新版格式兼容）。
 * 纯 JVM，不依赖 Robolectric。
 */
class AddFriendPayloadTest {

    private val security = SecureRandom()

    private fun random(n: Int) = ByteArray(n).also(security::nextBytes)

    private fun payload(naddr: String = "") =
        AddFriendPayload(
            name = "aabbccddeeff0011",
            identity = random(33),
            bundle = random(1792),
            bucket = random(32),
            token = random(48),
            ble = random(8),
            naddr = naddr,
            expiresAtMs = 1_800_000_000_000L,
        )

    /** 与 Rust `naddr_string` 输出同构的节点快照（64 hex id + b64url sockaddr）。 */
    private fun sampleNaddr(): String {
        val id = "ab".repeat(32) // 64 hex chars = 32 字节节点 id
        val addr = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(byteArrayOf(10, 0, 0, 2, 0x81.toByte(), 0x88.toByte())) // 10.0.0.2:33160
        return "dc://node?v=1&id=$id&a=$addr"
    }

    // ---------- naddr 编码/解析 ----------

    @Test
    fun encode_parse_roundtrip_with_naddr() {
        val naddr = sampleNaddr()
        val p = payload(naddr = naddr)
        val uri = p.encode()
        val parsed = AddFriendPayload.parse(uri)
        assert(parsed != null)
        assertEquals(naddr, parsed!!.naddr)
        assertEquals(p.name, parsed.name)
        assertArrayEquals(p.identity, parsed.identity)
        assertArrayEquals(p.bucket, parsed.bucket)
        assertArrayEquals(p.token, parsed.token)
        assertArrayEquals(p.ble, parsed.ble)
        assertEquals(p.expiresAtMs, parsed.expiresAtMs)
    }

    @Test
    fun encode_parse_roundtrip_without_naddr_is_backward_compatible() {
        val p = payload(naddr = "")
        val parsed = AddFriendPayload.parse(p.encode())
        assert(parsed != null)
        assertEquals("", parsed!!.naddr)
    }

    @Test
    fun parse_rejects_naddr_with_bad_base64() {
        // naddr 字段必须是合法 b64url；非法 → 整体载荷解析失败（fail-closed）
        val p = payload(naddr = sampleNaddr())
        val badUri = p.encode().replace(
            java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sampleNaddr().toByteArray(Charsets.UTF_8)),
            "!!!not-b64!!!",
        )
        assertNull(AddFriendPayload.parse(badUri))
    }

    // ---------- DCS1 握手载荷解析（P0 双向地址交换） ----------

    @Test
    fun parse_dcs1_old_format_returns_secret_and_empty_naddr() {
        val secret = random(32)
        val plain = "DCS1".toByteArray(Charsets.US_ASCII) + secret
        val (gotSecret, naddr) = parseDcs1(plain)!!
        assertArrayEquals(secret, gotSecret)
        assertEquals("", naddr)
    }

    @Test
    fun parse_dcs1_with_appended_host_naddr() {
        val secret = random(32)
        val naddr = sampleNaddr()
        val plain = "DCS1".toByteArray(Charsets.US_ASCII) + secret +
            byteArrayOf(0) + naddr.toByteArray(Charsets.US_ASCII)
        val (gotSecret, gotNaddr) = parseDcs1(plain)!!
        assertArrayEquals(secret, gotSecret)
        assertEquals(naddr, gotNaddr)
    }

    @Test
    fun parse_dcs1_rejects_invalid_formats() {
        assertNull(parseDcs1(ByteArray(0)))
        assertNull(parseDcs1("DCS1".toByteArray(Charsets.US_ASCII) + ByteArray(31)))
        // 前缀不是 DCS1
        assertNull(parseDcs1("XXXX".toByteArray(Charsets.US_ASCII) + random(32)))
        // 4+32 之后跟非 0x00 分隔符（如 0x01）→ 拒绝
        val bad = "DCS1".toByteArray(Charsets.US_ASCII) + random(32) + byteArrayOf(1) + "x".toByteArray()
        assertNull(parseDcs1(bad))
    }
}