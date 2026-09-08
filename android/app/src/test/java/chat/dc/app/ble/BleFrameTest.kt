package chat.dc.app.ble

import org.junit.Assert.assertEquals
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
}
