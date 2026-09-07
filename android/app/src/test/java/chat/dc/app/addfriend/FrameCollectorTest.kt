package chat.dc.app.addfriend

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * 动态分帧二维码核心逻辑（纯 JVM）：
 * 分帧重组往返 / 噪声帧与异会话帧必须忽略 / 3 秒时长门槛 / 顺序无关。
 */
class FrameCollectorTest {

    private val security = SecureRandom()

    private fun payloadAndFrames(): Pair<AddFriendPayload, List<String>> {
        val p = AddFriendPayload.generate(security)
        val sid = "aabbccdd"
        return p to FrameCodec.split(p, sid)
    }

    @Test
    fun split_then_collect_roundtrip_in_any_order_with_noise() {
        val (payload, frames) = payloadAndFrames()
        val collector = FrameCollector()
        // 乱序 + 噪声 + 重复帧，全部喂入
        val mixed = frames.shuffled(security) + FrameCodec.noiseFrame("aabbccdd", security) + frames.first()
        var st = collector.snapshot(0)
        var t = 1000L
        for (f in mixed) {
            st = collector.onFrame(f, t)
            t += 100
        }
        // 集齐但时长不足（1000..1600 < 3000ms 门槛）：未完成
        assertFalse(st.complete)
        assertNull(st.payload)
        // 时间窗满足后完成，重组载荷与原件一致
        st = collector.snapshot(4100)
        assertTrue(st.complete)
        assertEquals(payload.encode(), st.payload!!.encode())
        assertEquals(frames.size, st.total)
    }

    @Test
    fun gate_requires_three_seconds_even_if_all_chunks_seen() {
        val (_, frames) = payloadAndFrames()
        val collector = FrameCollector()
        frames.forEachIndexed { i, f ->
            val st = collector.onFrame(f, 1000L + i)
            if (i < frames.lastIndex) assertFalse(st.complete)
        }
        // 全部帧已见，但只过了 500ms
        assertFalse(collector.snapshot(1500).complete)
        assertTrue(collector.snapshot(1000 + FrameCodec.MIN_COLLECT_MS).complete)
    }

    @Test
    fun frames_from_other_session_do_not_pollute() {
        val (_, frames) = payloadAndFrames()
        val other = AddFriendPayload.generate(security)
        val otherFrames = FrameCodec.split(other, "ffff0000")
        val collector = FrameCollector()
        // 先喂本会话帧（锁定），再喂异会话帧：不得污染本会话进度
        frames.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        otherFrames.forEach { collector.onFrame(it, 2000L) }
        val st = collector.snapshot(1000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        // 完成会话帧数 = 本会话帧数，而非异会话
        assertEquals(frames.size, st.total)
    }

    @Test
    fun reset_clears_lock_so_new_session_can_be_collected() {
        val (_, frames) = payloadAndFrames()
        val other = AddFriendPayload.generate(security)
        val otherFrames = FrameCodec.split(other, "ffff0000")
        val collector = FrameCollector()
        frames.forEach { collector.onFrame(it, 1000L) }
        collector.reset()
        otherFrames.forEachIndexed { i, f -> collector.onFrame(f, 5000L + i) }
        val st = collector.snapshot(5000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(other.encode(), st.payload!!.encode())
    }

    @Test
    fun non_frame_text_ignored() {
        val collector = FrameCollector()
        collector.onFrame("https://example.com/something", 1000)
        collector.onFrame("random junk", 1000)
        assertEquals(0, collector.snapshot(1000).collected)
    }

    @Test
    fun chunk_count_matches_payload_size() {
        val (_, frames) = payloadAndFrames()
        // 载荷 ~180 字符，48 字符/帧 → 4 帧；防 CHUNK_SIZE 改动导致帧数失控
        assertTrue("帧数应在 2..8: ${frames.size}", frames.size in 2..8)
        assertTrue(frames.all { it.startsWith(FrameCodec.FRAME_PREFIX) })
    }
}
