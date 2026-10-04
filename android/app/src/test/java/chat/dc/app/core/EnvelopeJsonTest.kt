package chat.dc.app.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** EnvelopeJson 编解码：纯 JVM，不依赖 native。 */
class EnvelopeJsonTest {

    @Test
    fun build_produces_serde_shape_and_parses_back() {
        val msgId = ByteArray(16) { it.toByte() }
        val sender = ByteArray(32) { 7 }
        val recipient = ByteArray(32) { 9 }
        val body = byteArrayOf(1, 2, 3, 4)
        val json = EnvelopeJson.buildText(msgId, sender, recipient, body, 123456789L)

        // serde 形状：无 sig 字段、kind 为字符串、数组为数字数组
        assertTrue(json.startsWith("{\"msg_id\":["))
        assertTrue(json.contains("\"kind\":\"Text\""))
        assertTrue(!json.contains("\"sig\""))

        val env = EnvelopeJson.parse(json)!!
        assertArrayEquals(msgId, env.msgId)
        assertArrayEquals(recipient, env.recipient)
        assertArrayEquals(body, env.body)
        assertEquals(123456789L, env.sentAtMs)
    }

    @Test
    fun parse_handles_null_recipient() {
        // 群播/中继信封形状：recipient=null，group 非空（本应用不投递此类）
        val json = """{"msg_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],""" +
            """"sender":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],""" +
            """"recipient":null,"group":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],""" +
            """"kind":"Text","body":[5,6,7],"sent_at_ms":42,"ttl_hops":6}"""
        val env = EnvelopeJson.parse(json)!!
        assertNull(env.recipient)
        assertArrayEquals(byteArrayOf(5, 6, 7), env.body)
    }

    @Test
    fun parse_rejects_garbage() {
        assertNull(EnvelopeJson.parse("not json"))
        assertNull(EnvelopeJson.parse("{}"))
        assertNull(EnvelopeJson.parse("""{"msg_id":null}"""))
        // recipient 长度不对（31）→ 解析失败
        val bad = """{"msg_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],""" +
            """"sender":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],""" +
            """"recipient":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],""" +
            """"kind":"Text","body":[5],"sent_at_ms":42,"ttl_hops":6}"""
        assertNull(EnvelopeJson.parse(bad))
    }
}