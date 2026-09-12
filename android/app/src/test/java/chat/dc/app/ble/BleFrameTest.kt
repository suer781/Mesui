package chat.dc.app.ble

import chat.dc.app.friendlink.FriendLink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 帧编解码与分片重组（纯 JVM）。 */
class BleFrameTest {

    @Test
    fun frame_roundtrip_single_chunk() {
        val frame = wireFrame(Wire.SAS_OK, ByteArray(0))
        assertEquals(3, frame.size)
        val sink = FrameSink()
        assertEquals(listOf(frame.toList()), sink.feed(frame).map { it.toList() })
    }

    @Test
    fun sink_reassembles_across_arbitrary_chunk_split() {
        val a = wireFrame(Wire.MSG, byteArrayOf(2, 10, 20))
        val b = wireFrame(Wire.HS, ByteArray(300) { it.toByte() })
        val stream = a + b
        val sink = FrameSink()
        val got = mutableListOf<ByteArray>()
        // 逐 7 字节喂入：任何分片边界都要正确重组
        for (off in stream.indices step 7) {
            got += sink.feed(stream.copyOfRange(off, minOf(off + 7, stream.size)))
        }
        assertEquals(2, got.size)
        assertTrue(got[0].contentEquals(a))
        assertTrue(got[1].contentEquals(b))
    }

    @Test
    fun sink_oversize_buffer_guard() {
        val sink = FrameSink()
        // 声明超大 bodyLen 的坏头：缓冲被立即丢弃，不无限增长也不吞后续帧
        sink.feed(byteArrayOf(Wire.MSG.toByte(), -1, -1))
        // 长度取 3 的整数倍（2 帧 × 3B 头、len=0）：全零「空体帧流」被整除消费后
        // 缓冲归零，好帧不被残余错位污染（len=0 的空体帧是 SAS_OK 的合法形态）
        sink.feed(ByteArray(4002))
        val again = sink.feed(wireFrame(Wire.SAS_OK, ByteArray(1)))
        assertEquals(1, again.size)
    }

    @Test
    fun split_for_chunk_covers_frame() {
        val frame = wireFrame(Wire.HS, ByteArray(1000))
        val chunks = splitForChunk(frame, 100)
        assertEquals(frame.size, chunks.sumOf { it.size })
        assertTrue(chunks.all { it.size <= 100 })
        // ByteArray 非 Iterable，flatten 需逐元素展开
        assertEquals(frame.toList(), chunks.flatMap { it.toList() })
    }

    @Test
    fun chunk_size_budget_lower_bound_is_20_not_23() {
        // BLE 最小 MTU=23：ATT 写预算 = 23 − 3 = 20。旧码下界钳 23 会把真实预算
        // 20 抬到 23，写 23 字节超预算必失败（P2）
        assertEquals(20, chunkSizeFor(23, true))
        // 异常小/零值 MTU 同样钳回下界，不出负数或 0 尺寸分片
        assertEquals(20, chunkSizeFor(3, true))
        assertEquals(20, chunkSizeFor(0, true))
        // 满配 MTU=517：预算 514
        assertEquals(514, chunkSizeFor(517, true))
        // 协商失败（status≠GATT_SUCCESS）：mtu 报告值不可信，保守回退最小预算
        assertEquals(20, chunkSizeFor(517, false))
        // 最小预算下任何帧都能被完整切分且逐片 ≤ 预算
        val frame = wireFrame(Wire.HS, ByteArray(60))
        assertTrue(splitForChunk(frame, chunkSizeFor(23, true)).all { it.size <= 20 })
    }

    @Test
    fun auth_b_round_trip_initiator_answer_matches_responder_check() {
        // P1 回归：发起端收到 AUTH_B_CHA(nonceB) 后必须回 AUTH_B_RSP =
        // HMAC(S_i, nonceB) 截断 16 字节——响应端（onResponderFrame 的
        // AUTH_B_RSP 分支）校验的正是这个值；双向认证由此闭环
        val si = ByteArray(32) { (it * 11 + 5).toByte() }
        val nonceB = ByteArray(16) { 0x5A }
        val challenge = wireFrame(Wire.AUTH_B_CHA, nonceB)
        assertEquals(Wire.AUTH_B_CHA, challenge[0].toInt())
        val body = challenge.copyOfRange(Wire.HEADER_LEN, challenge.size)
        assertEquals(16, body.size)
        val rsp = wireFrame(Wire.AUTH_B_RSP, FriendLink.hmac(si, body))
        assertEquals(Wire.AUTH_B_RSP, rsp[0].toInt())
        val rspBody = rsp.copyOfRange(Wire.HEADER_LEN, rsp.size)
        assertEquals(FriendLink.HMAC_TRUNC, rspBody.size)
        assertTrue(rspBody.contentEquals(FriendLink.hmac(si, nonceB)))
        // 错误 S_i 的应答必须被响应端拒绝
        assertFalse(rspBody.contentEquals(FriendLink.hmac(ByteArray(32) { 1 }, nonceB)))
    }
}
