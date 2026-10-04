package chat.dc.app.core

import chat.dc.core.DcException
import chat.dc.core.DeliveryManagerHandle
import chat.dc.core.SendCallback
import chat.dc.core.TickReportRecord
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * 投递队列 FFI 往返测试（纯 JVM，不依赖 BLE 硬件）：
 * 直接调用 [DeliveryManagerHandle]（与 Kotlin 生产代码经同一 UniFFI 绑定），
 * 用 fake [SendCallback] 验证 enqueue → tick → 送达 / 退避重试 / 死信 / revive /
 * cleanup 全路径。需要本机构建好的 dc_core.dll（cargo build -p dc-core --features ffi）。
 */
class DeliveryManagerHandleTest {

    companion object {
        /** 核心库所在目录。CI 可经 DC_CORE_LIB 环境变量（或 -Ddc.core.lib 系统属性）
         *  注入 Linux 的 libdc_core.so 所在目录；未注入时回退本机 Windows 默认
         *  构建路径。 */
        private val LIB_DIR: String = run {
            val injected = System.getenv("DC_CORE_LIB")?.takeIf { it.isNotBlank() }
                ?: System.getProperty("dc.core.lib")?.takeIf { it.isNotBlank() }
            injected ?: "C:/Users/13682/cargo-target/dc-chat/debug"
        }
        private const val MINGW_BIN = "C:/Users/13682/msys64/mingw64/bin"

        /** 当前平台的核心库文件名：Windows 为 dc_core.dll，Linux/macOS 为 libdc_core.so。 */
        private val LIB_NAME =
            if ((System.getProperty("os.name") ?: "").lowercase().contains("windows")) "dc_core.dll" else "libdc_core.so"

        init {
            // 让 JNA 找到核心库（及 OpenSSL 依赖库所在目录）
            val dirs = listOf(LIB_DIR, MINGW_BIN).filter { File(it).isDirectory }
            System.setProperty("jna.library.path", dirs.joinToString(";"))
            // 预加载 OpenSSL 依赖（仅 Windows 需要）：Windows LoadLibrary 对依赖库
            // 按 PATH 解析，先加载可避免 dc_core.dll 因依赖缺失而加载失败
            runCatching { com.sun.jna.Native.load("libcrypto-3-x64", com.sun.jna.Library::class.java) }
            runCatching { com.sun.jna.Native.load("libssl-3-x64", com.sun.jna.Library::class.java) }
        }
    }

    private val delivered = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
    @Volatile private var fail = false
    private var handle: DeliveryManagerHandle? = null

    @Before
    fun setUp() {
        assumeTrue(
            "核心库未构建（需先 cargo build -p dc-core --features ffi；CI 可用 DC_CORE_LIB 注入 libdc_core.so 目录），跳过 native 用例",
            File(LIB_DIR, LIB_NAME).exists(),
        )
        fail = false
        delivered.clear()
        handle = newHandle()
    }

    @After
    fun tearDown() {
        handle?.close()
        handle = null
    }

    private fun newHandle(): DeliveryManagerHandle {
        val cb = object : SendCallback {
            override fun send(envelopeJson: String): Boolean {
                val env = EnvelopeJson.parse(envelopeJson) ?: return false
                if (fail) return false // Ok(false)：对方不可达，tick 按退避重试
                delivered.add(env.body)
                return true
            }
        }
        return DeliveryManagerHandle(":memory:", "testkey1234", cb)
    }

    private fun env(msgIdFirst: Int, sentAtMs: Long): String {
        val msgId = ByteArray(16) { (msgIdFirst + it).toByte() }
        return EnvelopeJson.buildText(
            msgId = msgId,
            sender = ByteArray(32) { 7 },
            recipient = ByteArray(32) { 9 },
            body = byteArrayOf(1, 2, 3),
            sentAtMs = sentAtMs,
        )
    }

    @Test
    fun enqueue_tick_delivers_via_callback() {
        val h = handle!!
        h.enqueue(env(1, 1000))
        h.enqueue(env(2, 2000))
        val rep = h.tick(3000L.toULong())
        assertEquals(2u, rep.attempted)
        assertEquals(2u, rep.sent)
        assertEquals(0u, rep.unreachable)
        assertEquals(0u, rep.dead)
        assertEquals(2, delivered.size)
        assertTrue(delivered.all { it.contentEquals(byteArrayOf(1, 2, 3)) })
        assertEquals(listOf(0u, 0u, 0u), h.stats())
    }

    @Test
    fun offline_waits_then_dead_then_revive() {
        val h = handle!!
        fail = true
        h.enqueue(env(3, 1000))
        // 默认策略 8 次：每拍推进 max_delay+1ms，8 拍耗尽 → 死信
        val step = 15L * 60 * 1000 + 1
        var last = TickReportRecord(0u, 0u, 0u, 0u, 0u)
        for (i in 1..8L) {
            last = h.tick((i * step).toULong())
            if (i < 8) assertEquals("前 7 拍不转死信（第 $i 拍）", 0u, last.dead)
        }
        assertEquals(1u, last.dead)
        assertEquals(listOf(0u, 1u, 0u), h.stats())
        assertEquals(1, h.deadLetters(10u).size)
        // 用户复活 → 回调改可达（重绑）→ 下一拍送达
        h.revive(h.deadLetters(10u)[0])
        fail = false
        val rep = h.tick((100L * step).toULong())
        assertEquals(1u, rep.attempted)
        assertEquals(1u, rep.sent)
        assertEquals(listOf(0u, 0u, 0u), h.stats())
    }

    @Test
    fun unreachable_stays_queued_and_cleanup_runs() {
        val h = handle!!
        fail = true
        h.enqueue(env(4, 1000))
        val rep = h.tick(1000L.toULong())
        assertEquals(1u, rep.attempted)
        assertEquals(1u, rep.unreachable)
        assertEquals(0u, rep.sent)
        assertEquals(listOf(1u, 0u, 0u), h.stats()) // 离线消息滞留队列不丢
        // 摘除通道 → tick no-op
        h.clearCallback()
        assertEquals(TickReportRecord(0u, 0u, 0u, 0u, 0u), h.tick(99_999L.toULong()))
        // 清理（空台账/无死信）幂等无错
        val c = h.cleanup(1_000_000L.toULong())
        assertEquals(0u, c.prunedSeen)
        assertEquals(0u, c.prunedDead)
        // 坏 JSON / 坏 hex 各自被拒
        expectDcException { h.enqueue("not json") }
        expectDcException { h.revive("zz".repeat(16)) }
        expectDcException { h.revive("ab".repeat(8)) }
        assertTrue(h.deadLetters(10u).isEmpty())
    }

    private fun expectDcException(block: () -> Unit) {
        try {
            block()
            assertTrue("应抛 DcException", false)
        } catch (_: DcException) {
            // expected
        }
    }
}