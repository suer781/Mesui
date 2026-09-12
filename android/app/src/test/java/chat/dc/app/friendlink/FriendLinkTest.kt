package chat.dc.app.friendlink

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 好友回连匹配层（纯 JVM）：派生链确定性、槽位/日轮换、布隆构建与查询、
 * HMAC 校验、负载编解码。
 */
class FriendLinkTest {

    private fun secret(b: Int) = ByteArray(32) { (b * 7 + it).toByte() }

    @Test
    fun slotId_is_deterministic_and_differs_across_slots() {
        val s = secret(1)
        assertArrayEquals(FriendLink.slotId(s, 100L), FriendLink.slotId(s, 100L))
        assertFalse(FriendLink.slotId(s, 100L).contentEquals(FriendLink.slotId(s, 101L)))
        assertFalse(FriendLink.slotId(s, 100L).contentEquals(FriendLink.slotId(secret(2), 100L)))
    }

    @Test
    fun bloom_contains_all_friend_ids() {
        val secrets = (1..20).map { secret(it) }
        val slot = 555L
        val bloom = FriendLink.buildBloom(secrets, slot, ByteArray(2048) { (it * 31).toByte() })
        assertEquals(128, bloom.size)
        secrets.forEach { assertTrue("缺失好友 ID", FriendLink.bloomHit(bloom, FriendLink.slotId(it, slot))) }
    }

    @Test
    fun bloom_membership_hidden_from_non_friends_is_rare() {
        val friends = (1..50).map { secret(it) }
        val bloom = FriendLink.buildBloom(friends, 9L, ByteArray(2048) { (it * 17 + 3).toByte() })
        // 200 个非好友假阳性率期望 ~k 次概率级；断言阈值给足余量防 flaky
        val fps = (100..300).count { FriendLink.bloomHit(bloom, FriendLink.slotId(secret(it), 9L)) }
        assertTrue("非好友命中率应远低于真好友: $fps", fps < 60)
    }

    @Test
    fun set_bits_padded_to_fixed_target_regardless_of_friend_count() {
        val pad = ByteArray(4096) { (it * 13 + 7).toByte() }
        fun setBits(b: ByteArray): Int = b.sumOf { byte ->
            (0..7).count { bit -> (byte.toInt() shr bit) and 1 == 1 }
        }
        val few = FriendLink.buildBloom(listOf(secret(1)), 3L, pad)
        val many = FriendLink.buildBloom((1..40).map { secret(it) }, 3L, pad)
        // 填充使 set-bit 数逼近同一目标（±2%），不泄露真实好友数
        assertTrue("set bits 偏差过大: ${setBits(few)} vs ${setBits(many)}",
            kotlin.math.abs(setBits(few) - setBits(many)) <= FriendLink.HASHES * FriendLink.CAP_FRIENDS * 2 / 100 + FriendLink.HASHES)
    }

    @Test
    fun candidates_returns_friend_indices_matching_bloom() {
        val secrets = (1..10).map { secret(it) }
        val slot = 777L
        val bloom = FriendLink.buildBloom(secrets, slot, ByteArray(2048) { it.toByte() })
        val hit = FriendLink.candidates(bloom, secrets, slot)
        assertTrue("全部真好友应进候选", hit.size >= secrets.size - 1)
        assertTrue(hit.all { (i, _) -> i in secrets.indices })
    }

    @Test
    fun candidates_prev_slot_tolerates_clock_skew() {
        val secrets = listOf(secret(5))
        val prevSlot = 400L
        val bloom = FriendLink.buildBloom(secrets, prevSlot, ByteArray(2048) { it.toByte() })
        // 扫描方处于下一槽（广播方还没轮换）：前一槽容忍窗口仍命中
        val hit = FriendLink.candidates(bloom, secrets, prevSlot + 1)
        assertTrue("跨槽边界必须容忍", hit.isNotEmpty())
    }

    @Test
    fun hmac_verifies_and_rejects_wrong_secret() {
        val nonce = ByteArray(16) { 0x33 }
        val mac = FriendLink.hmac(secret(1), nonce)
        assertEquals(16, mac.size)
        assertArrayEquals(mac, FriendLink.hmac(secret(1), nonce))
        assertFalse(mac.contentEquals(FriendLink.hmac(secret(2), nonce)))
    }

    @Test
    fun advertise_payload_roundtrip_and_rejects_bad() {
        val bloom = FriendLink.buildBloom(listOf(secret(1)), 2L, ByteArray(2048))
        val wire = FriendLink.advertisePayload(bloom)
        assertEquals(129, wire.size)
        assertArrayEquals(bloom, FriendLink.parseAdvertisePayload(wire))
        assertNull(FriendLink.parseAdvertisePayload(wire.copyOfRange(0, 50)))
        assertNull(FriendLink.parseAdvertisePayload(ByteArray(129))) // 版本 0 不符
        assertNull(FriendLink.parseAdvertisePayload(null))
    }
}
