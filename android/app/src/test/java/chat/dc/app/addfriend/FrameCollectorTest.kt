package chat.dc.app.addfriend

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * 动态分帧二维码核心逻辑（纯 JVM）：
 * 分帧重组往返 / 噪声帧与异会话帧必须忽略 / 3 秒时长门槛 / 顺序无关 /
 * 帧级 CRC 校验（坏帧拒收、重传恢复）/ 串行攻击（同 sid 异内容必须拒绝）/
 * 锁超时自愈 / 自适应帧率节拍器 / 蓝牙连接帧（f=2 快连搭线：立即回调、
 * 门槛不变、旧解析不误收）/ 每轮随机盐 nonce（字节层每轮刷新、sid 与数据
 * 内容不变、跨轮帧互通）/ 两阶段展示序列（f=2 与 f=1 绝不同序列、降级交替）/
 * 前向纠错（f=3 奇偶帧：丢 1 帧 XOR 即时恢复、不锁会话不占位、坏奇偶帧拒收）。
 */
class FrameCollectorTest {

    private val security = SecureRandom()

    /** 真实载荷同构的字段尺寸：identity 33 字节（libsignal IdentityKey::serialize，
     *  含 1 字节类型前缀），bundle 含 Kyber-1024 公钥约 1.8KB。 */
    private fun random(n: Int) = ByteArray(n).also(security::nextBytes)

    private fun payload(name: String = "aabbccddeeff0011") =
        AddFriendPayload(name, random(33), random(1792), random(32), random(48), random(8))

    /** 蓝牙连接帧搭线信息（sid 16 hex，同 [FrameCodec.SID_LEN]；bleId 8B、challenge 16B）。 */
    private fun bleInfo(sid: String = "aabbccddeeff0011") = BleConnectInfo(
        sid = sid,
        name = "aabbccddeeff0011",
        bleId = random(8),
        serviceUuid = "8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e5f",
        challenge = random(16),
    )

    private fun feed(collector: FrameCollector, frames: List<String>, startMs: Long, stepMs: Long = 100L) {
        var t = startMs
        frames.forEach { f ->
            collector.onFrame(f, t)
            t += stepMs
        }
    }

    /** 篡改帧的 d 段首字符（模拟扫码误读；仍在 b64url 字母表内，
     *  parse 可过、CRC 必挂）。 */
    private fun tamperData(frame: String): String {
        val dIdx = frame.indexOf("&d=")
        val c = frame[dIdx + 3]
        val swapped = if (c == 'A') 'B' else 'A'
        return frame.substring(0, dIdx + 3) + swapped + frame.substring(dIdx + 4)
    }

    /** 模拟有能力的攻击者：任选 sid + 任选载荷内容，逐帧自行重算 CRC 的完整帧组。 */
    private fun forgeFrames(sid: String, payloadText: String): List<String> {
        val n = (payloadText.length + FrameCodec.CHUNK_SIZE - 1) / FrameCodec.CHUNK_SIZE
        return (0 until n).map { i ->
            val d = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                payloadText
                    .substring(i * FrameCodec.CHUNK_SIZE, minOf((i + 1) * FrameCodec.CHUNK_SIZE, payloadText.length))
                    .toByteArray(Charsets.UTF_8),
            )
            FrameCodec.buildFrame(sid, i, n, noise = false, data = d)
        }
    }

    // ---------- 回归：分帧重组 / 时长门槛 / 异会话隔离 ----------

    @Test
    fun split_then_collect_roundtrip_in_any_order_with_noise() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val collector = FrameCollector()
        // 乱序 + 噪声 + 重复帧，全部喂入
        val mixed = frames.shuffled(security) +
            FrameCodec.noiseFrame(FrameCodec.sidOf(p), security) + frames.first()
        var st = collector.snapshot(0)
        var t = 1000L
        for (f in mixed) {
            st = collector.onFrame(f, t)
            t += 100
        }
        // 集齐但时长不足（1000..2200 < 3000ms 门槛）：未完成
        assertFalse(st.complete)
        assertNull(st.payload)
        // 时间窗满足后完成，重组载荷与原件一致
        st = collector.snapshot(4100)
        assertTrue(st.complete)
        assertEquals(p.encode(), st.payload!!.encode())
        assertEquals(frames.size, st.total)
        assertEquals(emptyList<Int>(), st.missing)
    }

    @Test
    fun gate_requires_three_seconds_even_if_all_chunks_seen() {
        val frames = FrameCodec.split(payload())
        val collector = FrameCollector()
        frames.forEachIndexed { i, f ->
            val st = collector.onFrame(f, 1000L + i)
            if (i < frames.lastIndex) assertFalse(st.complete)
        }
        // 全部帧已见，但只过了 ~0ms
        assertFalse(collector.snapshot(1500).complete)
        assertTrue(collector.snapshot(1000 + FrameCodec.MIN_COLLECT_MS).complete)
    }

    @Test
    fun frames_from_other_session_do_not_pollute() {
        val a = payload()
        val aFrames = FrameCodec.split(a)
        val other = payload("ffff0000ffff0000")
        val otherFrames = FrameCodec.split(other)
        val collector = FrameCollector()
        // 先喂本会话帧（锁定），再喂异会话帧：不得污染本会话进度
        aFrames.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        otherFrames.forEach { collector.onFrame(it, 2000L) }
        val st = collector.snapshot(1000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        // 完成会话帧数 = 本会话帧数，而非异会话；异会话帧计入拒绝
        assertEquals(aFrames.size, st.total)
        assertEquals(otherFrames.size, st.rejected)
    }

    @Test
    fun reset_clears_lock_so_new_session_can_be_collected() {
        val a = payload()
        val collector = FrameCollector()
        FrameCodec.split(a).forEach { collector.onFrame(it, 1000L) }
        collector.reset()
        val b = payload("ffff0000ffff0000")
        val bFrames = FrameCodec.split(b)
        bFrames.forEachIndexed { i, f -> collector.onFrame(f, 5000L + i) }
        val st = collector.snapshot(5000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(b.encode(), st.payload!!.encode())
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
        val p = payload()
        val frames = FrameCodec.split(p)
        // 真实载荷约 2.6KB，256 字符/帧 → 约 11 帧；防 CHUNK_SIZE 改动导致帧数失控
        assertTrue("帧数应在 4..24: ${frames.size}", frames.size in 4..24)
        assertTrue(frames.all { it.startsWith(FrameCodec.FRAME_PREFIX) })
        // 每帧都过帧级校验，且 sid 与载荷内容哈希一致
        val sid = FrameCodec.sidOf(p)
        assertTrue(frames.all { FrameCodec.verify(it)?.sid == sid })
    }

    // ---------- 帧级 CRC 校验：坏帧可检出、重传可恢复 ----------

    @Test
    fun frame_carries_crc_and_tampering_is_detected() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val f = FrameCodec.parse(frames[0])!!
        // 帧内 c 字段与内容一致（CRC32 over sid|i|n|f|d）
        assertEquals(FrameCodec.crcOf(f.sid, f.index, f.total, f.noise, f.data), f.crc)
        // 篡改 d 段一个字符 → verify 拒绝
        assertNull(FrameCodec.verify(tamperData(frames[0])))
        // 缺 c 字段的帧（旧 v1 / 被剥掉校验字段）解析即拒
        assertNull(FrameCodec.parse(frames[0].replace(Regex("&c=[0-9a-f]{8}"), "")))
        // 噪声帧同样携带有效 CRC（f=0），verify 可过、采集端另行忽略
        val noise = FrameCodec.noiseFrame(f.sid, security)
        assertTrue(FrameCodec.verify(noise)!!.noise)
    }

    @Test
    fun corrupt_frame_rejected_then_retransmit_recovers() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val collector = FrameCollector()
        // 误读帧：CRC 检出 → 不入库（静默收错才是 bug）
        val st1 = collector.onFrame(tamperData(frames[0]), 1000)
        assertEquals(0, st1.collected)
        assertEquals(1, st1.rejected)
        // 展示端循环重播同一帧 → 补齐，其余照常
        val st2 = collector.onFrame(frames[0], 1100)
        assertEquals(1, st2.collected)
        feed(collector, frames.drop(1), startMs = 1200)
        val done = collector.snapshot(1200 + frames.size * 100 + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertEquals(p.encode(), done.payload!!.encode())
        assertEquals(1, done.rejected)
    }

    @Test
    fun legacy_v1_frame_without_crc_is_ignored() {
        val collector = FrameCollector()
        collector.onFrame("dc://addframe?v=1&s=aaaaaaaaaaaaaaaa&i=0&n=1&f=1&d=QUJD", 1000)
        assertEquals(0, collector.snapshot(1000).collected)
        // v2 外观但缺 c 字段的非法帧：拒收并计数
        collector.onFrame(FrameCodec.FRAME_PREFIX + "s=aaaaaaaaaaaaaaaa&i=0&n=1&f=1&d=QUJD", 1100)
        assertEquals(1, collector.snapshot(1100).rejected)
    }

    // ---------- 串行攻击（扫一半换成别人的码） ----------

    @Test
    fun sid_is_content_hash_and_differs_across_payloads() {
        val p1 = payload()
        val p2 = payload("ffff0000ffff0000")
        // sid = 载荷内容哈希（挑战绑定）：同载荷确定、异载荷必异——
        // 「sid 相同但内容被替换」在数学上不可构造（哈希原像）；
        // 载荷含每场 SecureRandom 的 token/bucket/ble → sid 每次播放重生成
        assertEquals(FrameCodec.sidOf(p1), FrameCodec.sidOf(p1))
        assertNotEquals(FrameCodec.sidOf(p1), FrameCodec.sidOf(p2))
        assertEquals(FrameCodec.sidOf(p1), FrameCodec.parse(FrameCodec.split(p1).first())!!.sid)
    }

    @Test
    fun forged_full_set_with_victim_sid_is_rejected_by_content_gate() {
        val a = payload()
        val aFrames = FrameCodec.split(a)
        val aSid = FrameCodec.sidOf(a)
        val m = payload("ffff0000ffff0000")
        // 攻击者偷看/抢拍拿到 A 的 sid，把 M 自己的完整载荷包装成 A 的 sid
        //（CRC 逐帧自行重算 → 帧级校验全过），中途闪给采集端
        val forged = forgeFrames(aSid, m.encode())
        val collector = FrameCollector()
        // M 抢先：采集端锁定的是 A 的 sid、M 的内容
        feed(collector, forged, startMs = 1000L)
        // 内容门：H(重组文本) ≠ sid → 拒绝完成，且不清锁、等 A 的真帧逐槽覆盖
        val gateMs = 1000 + forged.size * 100 + FrameCodec.MIN_COLLECT_MS
        val gateSt = collector.snapshot(gateMs)
        assertFalse("同 sid 异内容帧组不得完成", gateSt.complete)
        assertTrue("内容门拒收应计数: ${gateSt.rejected}", gateSt.rejected >= 1)
        // A 的真帧随后到达（同载荷尺寸 → 同帧数）→ 门通过，完成的是 A 的载荷
        feed(collector, aFrames, startMs = gateMs + 200)
        val done = collector.snapshot(gateMs + 200 + aFrames.size * 100 + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertEquals(a.encode(), done.payload!!.encode())
    }

    @Test
    fun tampered_chunk_with_forged_crc_fails_gate_until_retransmit() {
        val a = payload()
        val frames = FrameCodec.split(a)
        val collector = FrameCollector()
        // 攻击者知道 sid/序号，可为篡改内容重算帧级 CRC——
        // 帧级校验只防误读不防伪造，真实性由内容门兜住
        val target = FrameCodec.parse(frames[2])!!
        val evilData = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random(64))
        collector.onFrame(frames[0], 1000)
        collector.onFrame(frames[1], 1100)
        collector.onFrame(FrameCodec.buildFrame(target.sid, 2, target.total, noise = false, data = evilData), 1200)
        feed(collector, frames.drop(3), startMs = 1300)
        // 内容门：被顶替的槽位使重组哈希 ≠ sid → 拒绝完成（不清锁）
        val gateMs = 1300 + frames.size * 100 + FrameCodec.MIN_COLLECT_MS
        assertFalse(collector.snapshot(gateMs).complete)
        // 展示端循环重播补上真帧 → 门通过
        collector.onFrame(frames[2], gateMs + 100)
        val done = collector.snapshot(gateMs + 100 + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertEquals(a.encode(), done.payload!!.encode())
    }

    // ---------- 锁超时自愈 ----------

    @Test
    fun lock_timeout_auto_resets_allowing_new_session() {
        val a = payload()
        val b = payload("ffff0000ffff0000")
        val collector = FrameCollector(minCollectMs = FrameCodec.MIN_COLLECT_MS, lockTimeoutMs = 2_000)
        // 锁定 A 后只来了一帧，A 随即离开/被遮挡（或攻击者占锁）
        collector.onFrame(FrameCodec.split(a).first(), 1000)
        // 超过锁超时后 B 出示：自动重置 → 锁定 B → 正常完成
        val bFrames = FrameCodec.split(b)
        feed(collector, bFrames, startMs = 5_000)
        assertEquals(FrameCodec.sidOf(b), collector.sid)
        val st = collector.snapshot(5_000 + bFrames.size * 100 + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(b.encode(), st.payload!!.encode())
    }

    // ---------- 自适应帧率节拍器 ----------

    @Test
    fun pacer_interval_is_max_of_encode_time_and_min_visual() {
        // 快设备：编码 20ms → 间隔 = 视觉下限 150（跑满设备能力，但不快过对面摄像头）
        val pacer = AdaptiveFramePacer(minVisualMs = 150)
        assertEquals(150L, pacer.afterEncode(20))
        assertEquals(150L, pacer.afterEncode(1))
        // 慢设备：持续 400ms 编码 → 间隔收敛到实测值，不被固定值拖垮
        val slow = AdaptiveFramePacer(minVisualMs = 150)
        assertEquals(400L, slow.afterEncode(400)) // 首样本直接锚定实测值
        var interval = 0L
        repeat(20) { interval = slow.afterEncode(400) }
        assertEquals(400L, interval)
    }

    @Test
    fun pacer_smooths_encode_spikes_with_ewma() {
        val pacer = AdaptiveFramePacer(minVisualMs = 150)
        pacer.afterEncode(400)
        // 单次抖动后回到快编码：EWMA 缓降，不跳变也不被尖峰卡死
        val next = pacer.afterEncode(100)
        assertTrue("间隔应介于两次实测之间: $next", next in 151..399)
        repeat(20) { pacer.afterEncode(100) }
        // 收敛到下限之下后由最小视觉间隔兜底
        assertEquals(150L, pacer.afterEncode(100))
    }

    // ---------- 蓝牙连接帧（f=2 快连搭线） ----------

    @Test
    fun ble_frame_roundtrip() {
        val info = bleInfo()
        val parsed = FrameCodec.parseBleFrame(FrameCodec.bleFrame(info))!!
        assertEquals(info.sid, parsed.sid)
        assertEquals(info.name, parsed.name)
        assertTrue(info.bleId.contentEquals(parsed.bleId))
        assertEquals(info.serviceUuid, parsed.serviceUuid)
        assertTrue(info.challenge.contentEquals(parsed.challenge))
    }

    @Test
    fun ble_frame_triggers_callback_immediately_and_gate_still_applies() {
        val info = bleInfo("aabbccddeeff0011")
        val collector = FrameCollector()
        var dialed: BleConnectInfo? = null
        var readyAt = -1L
        val ok = collector.tryBluetoothConnect(FrameCodec.bleFrame(info), 1000L) { i, at ->
            dialed = i
            readyAt = at
        }
        // 读到 f=2 即回调搭线信息，不等任何数据帧；就绪时点 = 首帧锚 + 3 秒门槛
        assertTrue(ok)
        assertTrue(info.bleId.contentEquals(dialed!!.bleId))
        assertEquals(1000L + FrameCodec.MIN_COLLECT_MS, readyAt)
        // 门槛未到：未完成，但蓝牙帧已在手
        val early = collector.snapshot(2000L)
        assertFalse(early.complete)
        assertNull(early.payload)
        assertTrue(info.bleId.contentEquals(early.ble!!.bleId))
        // 3 秒到即完成——无需任何数据帧（快连路径）
        val done = collector.snapshot(1000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertNull(done.payload)
        assertEquals(0, done.total) // 未锁定数据会话也不影响完成判定
    }

    @Test
    fun repeated_ble_frames_callback_once_other_session_ignored() {
        val info = bleInfo("aabbccddeeff0011")
        val other = bleInfo("ffffffffffffffff")
        val collector = FrameCollector()
        var calls = 0
        assertTrue(collector.tryBluetoothConnect(FrameCodec.bleFrame(info), 1000L) { _, _ -> calls += 1 })
        // 重复蓝牙帧：幂等，不重复回调
        assertTrue(collector.tryBluetoothConnect(FrameCodec.bleFrame(info), 1100L) { _, _ -> calls += 1 })
        assertEquals(1, calls)
        // 异会话蓝牙帧：拒绝，不挪锁
        assertFalse(collector.tryBluetoothConnect(FrameCodec.bleFrame(other), 1200L) { _, _ -> calls += 1 })
        assertEquals(1, calls)
        assertTrue(info.bleId.contentEquals(collector.snapshot(1200L).ble!!.bleId))
    }

    @Test
    fun ble_fast_path_and_legacy_collection_coexist_behind_same_gate() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val info = bleInfo(FrameCodec.sidOf(p))
        val collector = FrameCollector()
        // 蓝牙帧先到（快连搭线），数据帧随后照常采集
        collector.tryBluetoothConnect(FrameCodec.bleFrame(info), 1000L) { _, _ -> }
        var t = 1100L
        var st = collector.snapshot(0)
        for (f in frames) {
            st = collector.onFrame(f, t)
            t += 100
        }
        // 数据帧集齐但门槛未到：未完成（时长防偷拍门槛对快连同样生效）
        assertFalse(st.complete)
        // 门槛到期：完成，且数据帧重组仍然可用（旧路径共存，UI 自行择路）
        val done = collector.snapshot(1000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertEquals(p.encode(), done.payload!!.encode())
        assertEquals(emptyList<Int>(), done.missing)
    }

    @Test
    fun ble_frame_is_invisible_to_legacy_frame_parser() {
        val info = bleInfo()
        val frame = FrameCodec.bleFrame(info)
        // 旧版扫描端兼容：f=2 无 i/n → parse/verify 解析失败自动忽略；
        // 也不占数据帧位、不算噪声、不计拒绝
        assertNull(FrameCodec.parse(frame))
        assertNull(FrameCodec.verify(frame))
        val collector = FrameCollector()
        val st = collector.onFrame(frame, 1000L)
        assertEquals(0, st.collected)
        assertEquals(0, st.rejected)
    }

    @Test
    fun tryBluetoothConnect_rejects_non_ble_text() {
        val collector = FrameCollector()
        assertFalse(collector.tryBluetoothConnect("https://example.com/something", 0) { _, _ -> })
        assertFalse(collector.tryBluetoothConnect(FrameCodec.noiseFrame("aabbccddeeff0011", security), 0) { _, _ -> })
        // 数据帧不是蓝牙帧
        assertFalse(collector.tryBluetoothConnect(FrameCodec.split(payload()).first(), 0) { _, _ -> })
        // 篡改 d 段（CRC 挂）→ 解析拒绝
        val frame = FrameCodec.bleFrame(bleInfo())
        val dIdx = frame.indexOf("&d=")
        val tampered = frame.substring(0, dIdx + 3) + "B" + frame.substring(dIdx + 4)
        assertFalse(collector.tryBluetoothConnect(tampered, 0) { _, _ -> })
        assertEquals(null, collector.snapshot(0).ble)
    }

    @Test
    fun reset_clears_ble_lock_so_new_dial_can_bind() {
        val collector = FrameCollector()
        var calls = 0
        assertTrue(collector.tryBluetoothConnect(FrameCodec.bleFrame(bleInfo("aabbccddeeff0011")), 1000L) { _, _ -> calls += 1 })
        collector.reset()
        assertNull(collector.snapshot(1000L).ble)
        // 重置后异 sid 蓝牙帧可重新锁定并回调
        assertTrue(collector.tryBluetoothConnect(FrameCodec.bleFrame(bleInfo("ffffffffffffffff")), 2000L) { _, _ -> calls += 1 })
        assertEquals(2, calls)
        // 时长门槛重新锚定：reset 后首帧（蓝牙帧）重新起算
        assertFalse(collector.snapshot(2000L + FrameCodec.MIN_COLLECT_MS - 1).complete)
        assertTrue(collector.snapshot(2000L + FrameCodec.MIN_COLLECT_MS).complete)
    }

    // ---------- 每轮随机盐（nonce）：字节层每轮刷新、内容绑定不变 ----------

    /** 翻转帧内 x 段（nonce）首字符（模拟跨轮拼接/盐篡改；CRC 必挂）。 */
    private fun tamperNonce(frame: String): String {
        val xIdx = frame.indexOf("&x=")
        val c = frame[xIdx + 3]
        val swapped = if (c == '0') '1' else '0'
        return frame.substring(0, xIdx + 3) + swapped + frame.substring(xIdx + 4)
    }

    @Test
    fun nonce_changes_bytes_and_crc_but_not_sid_or_data() {
        val p = payload()
        val sid = FrameCodec.sidOf(p)
        val segs = FrameCodec.segments(p)
        val round1 = FrameCodec.buildFrame(sid, 0, segs.size, noise = false, data = segs[0], nonce = "01020304")
        val round2 = FrameCodec.buildFrame(sid, 0, segs.size, noise = false, data = segs[0], nonce = "090a0b0c")
        val legacy = FrameCodec.buildFrame(sid, 0, segs.size, noise = false, data = segs[0])
        // 同内容不同盐：字节层不同（防长曝光拼接），CRC 随盐重算
        assertNotEquals(round1, round2)
        assertNotEquals(round1, legacy)
        // 解析后 sid/序号/数据完全一致（sid 绑定载荷文本，与 nonce 无关）
        val f1 = FrameCodec.parse(round1)!!
        val f2 = FrameCodec.parse(round2)!!
        assertEquals(f1.sid, f2.sid)
        assertEquals(f1.data, f2.data)
        assertEquals("01020304", f1.nonce)
        assertEquals("090a0b0c", f2.nonce)
        // 各轮 verify 均过；盐被换（CRC 不再匹配）→ 拒收
        assertTrue(FrameCodec.verify(round1) != null)
        assertNull(FrameCodec.verify(tamperNonce(round1)))
        // 无盐旧式帧仍通过（向后兼容）
        assertTrue(FrameCodec.verify(legacy) != null)
    }

    @Test
    fun frames_from_different_nonce_rounds_mix_into_one_session() {
        val p = payload()
        val sid = FrameCodec.sidOf(p)
        val segs = FrameCodec.segments(p)
        // 同一张码的两轮循环（不同盐）混着扫：nonce 不参与内容绑定，照常重组
        val round1 = FrameCodec.dataPass(sid, segs, bleInfo = null, nonce = "01020304", security = security)
        val round2 = FrameCodec.dataPass(sid, segs, bleInfo = null, nonce = "090a0b0c", security = security)
        assertEquals(round1.size, round2.size)
        assertNotEquals(round1, round2)
        val mixed = round1.shuffled(security) + round2.shuffled(security)
        val collector = FrameCollector()
        mixed.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        val st = collector.snapshot(1000L + mixed.size + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(sid, collector.sid)
        assertEquals(p.encode(), st.payload!!.encode())
    }

    // ---------- 两阶段展示序列：f=2 与 f=1 绝不同序列 ----------

    @Test
    fun handshake_pass_contains_only_ble_frames() {
        val info = bleInfo()
        val pass = FrameCodec.handshakePass(info, "01020304")
        assertEquals(3, pass.size)
        pass.forEach {
            // 阶段 1 只滚 f=2 蓝牙帧（搭线），不出示任何数据帧
            assertEquals(info, FrameCodec.parseBleFrame(it))
            assertNull(FrameCodec.parse(it))
        }
        // 每轮换盐 → 字节层不同
        val next = FrameCodec.handshakePass(info, "090a0b0c")
        assertNotEquals(pass, next)
        assertTrue(next.all { FrameCodec.parseBleFrame(it) != null })
    }

    @Test
    fun exchange_pass_never_contains_ble_frames() {
        val p = payload()
        val sid = FrameCodec.sidOf(p)
        val segs = FrameCodec.segments(p)
        val pass = FrameCodec.dataPass(sid, segs, bleInfo = null, nonce = "01020304", security = security)
        assertTrue(pass.isNotEmpty())
        // 阶段 2：每帧都能被数据帧解析器解析（f=2 不可解析 → 混入即失败），
        // 且只有 数据/噪声/奇偶 三类
        val parsed = pass.map { FrameCodec.parse(it) }
        assertTrue("阶段 2 序列不得混入蓝牙帧（f=1/f=2 防混暴露）", parsed.all { it != null })
        val frames = parsed.filterNotNull()
        assertTrue(frames.any { !it.noise && !it.parity }) // 数据帧在场
        assertTrue(frames.any { it.parity }) // 奇偶帧在场
        // 每帧都过帧级校验（带盐 CRC）
        assertTrue(pass.all { FrameCodec.verify(it) != null })
        // 阶段 2 序列整体喂采集端 → 正常完成（两阶段不破坏旧解析/重组路径）
        val collector = FrameCollector()
        pass.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        val st = collector.snapshot(1000L + pass.size + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(p.encode(), st.payload!!.encode())
    }

    @Test
    fun fallback_pass_interleaves_data_and_ble_frames() {
        val p = payload()
        val sid = FrameCodec.sidOf(p)
        val segs = FrameCodec.segments(p)
        val info = bleInfo(sid)
        // 降级模式 = 旧式交替：蓝牙帧跟在每 2 个数据帧后（对方不支持快连的回退）
        val pass = FrameCodec.dataPass(sid, segs, bleInfo = info, nonce = "01020304", security = security)
        val kinds = pass.map { f ->
            when {
                FrameCodec.parseBleFrame(f) != null -> 2
                else -> FrameCodec.parse(f)!!.let { if (it.parity) 3 else if (it.noise) 0 else 1 }
            }
        }
        assertTrue(kinds.contains(1))
        assertTrue(kinds.contains(2))
        assertTrue(kinds.contains(3))
        // 旧式交替节奏：相邻蓝牙帧之间（含开头）恰好 2 个数据帧——噪声/奇偶帧
        // 只穿插，不改变 数据:蓝牙 = 2:1 的节奏（末尾余数 ≤ 2）
        var dataSinceBle = 0
        var bleSeen = 0
        kinds.forEach { k ->
            when (k) {
                1 -> dataSinceBle++
                2 -> {
                    assertEquals("每个蓝牙帧前应有恰好 2 个数据帧: $kinds", 2, dataSinceBle)
                    dataSinceBle = 0
                    bleSeen++
                }
            }
        }
        assertEquals(kinds.count { it == 1 } / 2, bleSeen)
        assertTrue("末尾数据帧余数应 ≤ 2: $kinds", dataSinceBle <= 2)
    }

    // ---------- 前向纠错（f=3 奇偶帧）：丢 1 帧 XOR 即时恢复 ----------

    /** 载荷全部 FEC 组的奇偶帧（f=3，无盐）。 */
    private fun parityFramesFor(p: AddFriendPayload): List<String> {
        val frames = FrameCodec.split(p)
        val sid = FrameCodec.sidOf(p)
        val total = frames.size
        val groups = FrameCodec.fecGroupCount(total)
        return (0 until groups).map { g ->
            val segs = FrameCodec.fecGroupIndices(total, g).map { FrameCodec.parse(frames[it])!!.data }
            FrameCodec.parityFrame(sid, g, groups, FrameCodec.parityOf(segs))
        }
    }

    @Test
    fun parity_frame_roundtrip_and_group_math() {
        val p = payload()
        val total = FrameCodec.split(p).size
        val groups = FrameCodec.fecGroupCount(total)
        assertEquals((total + FrameCodec.FEC_GROUP - 1) / FrameCodec.FEC_GROUP, groups)
        // 组下标不重不漏覆盖全部数据帧（末组可短于 FEC_GROUP）
        val covered = (0 until groups).flatMap { FrameCodec.fecGroupIndices(total, it) }
        assertEquals((0 until total).toList(), covered)
        // f=3 帧可解析、CRC 可校验；i/n = 组号/组数；非蓝牙帧
        val pf = parityFramesFor(p)
        assertEquals(groups, pf.size)
        pf.forEachIndexed { g, f ->
            val parsed = FrameCodec.verify(f)!!
            assertTrue(parsed.parity)
            assertFalse(parsed.noise)
            assertEquals(g, parsed.index)
            assertEquals(groups, parsed.total)
            assertNull(FrameCodec.parseBleFrame(f))
        }
    }

    @Test
    fun parity_frames_recover_single_missing_frame() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val pf = parityFramesFor(p)
        val collector = FrameCollector()
        // 组 0 丢第 1 帧（index 1）：CRC 没问题，就是没扫到
        val dropped = 1
        frames.filterIndexed { i, _ -> i != dropped }.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        val before = collector.snapshot(3000L)
        assertFalse(before.complete)
        assertEquals(listOf(dropped), before.missing)
        // 奇偶帧到场 → XOR 即时恢复，无须等循环重播
        pf.forEachIndexed { i, f -> collector.onFrame(f, 5000L + i) }
        val after = collector.snapshot(5000L + pf.size + FrameCodec.MIN_COLLECT_MS)
        assertTrue(after.complete)
        assertEquals(emptyList<Int>(), after.missing)
        assertEquals(1, after.recovered)
        assertEquals(p.encode(), after.payload!!.encode())
    }

    @Test
    fun parity_cannot_recover_two_missing_until_replay_fills_one() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val pf = parityFramesFor(p)
        val collector = FrameCollector()
        // 组 0 丢 2 帧（index 0、1）：单奇偶只能救 1 帧，先不动作
        val dropped = setOf(0, 1)
        frames.filterIndexed { i, _ -> i !in dropped }.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        pf.forEachIndexed { i, f -> collector.onFrame(f, 2000L + i) }
        val stuck = collector.snapshot(6000L)
        assertEquals(listOf(0, 1), stuck.missing)
        assertFalse(stuck.complete)
        // 循环重播补上其中 1 帧 → 另 1 帧立刻由奇偶帧恢复
        collector.onFrame(frames[0], 6100L)
        val done = collector.snapshot(6100L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(done.complete)
        assertEquals(emptyList<Int>(), done.missing)
        assertEquals(1, done.recovered)
        assertEquals(p.encode(), done.payload!!.encode())
    }

    @Test
    fun tampered_parity_frame_is_rejected_and_recovers_nothing() {
        val p = payload()
        val frames = FrameCodec.split(p)
        val pf = parityFramesFor(p)
        val collector = FrameCollector()
        val dropped = 2 // 组 0（下标 0..3）缺 index 2
        frames.filterIndexed { i, _ -> i != dropped }.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        // 组 0 的奇偶帧被篡改 → CRC 拒收、不恢复（宁可等重播也不静默收错）
        pf.forEachIndexed { i, f ->
            collector.onFrame(if (i == 0) tamperData(f) else f, 5000L + i)
        }
        val st = collector.snapshot(9000L)
        assertTrue(st.missing.contains(dropped))
        assertEquals(0, st.recovered)
        assertEquals(1, st.rejected)
        assertFalse(st.complete)
    }

    @Test
    fun parity_frames_do_not_lock_session_and_respect_it() {
        val p = payload()
        val pf = parityFramesFor(p)
        val collector = FrameCollector()
        // 未锁定时奇偶帧先到：不锁定会话（n 段是组数，锁定会错绑总数）、
        // 不计收、不计拒
        collector.onFrame(pf[0], 1000L)
        val unlocked = collector.snapshot(1000L)
        assertEquals(0, unlocked.collected)
        assertEquals(0, unlocked.rejected)
        assertNull(collector.sid)
        // 锁定正常会话后：同会话奇偶帧入库（组内无缺帧 → 不动作），完成不受干扰
        val other = payload("ffff0000ffff0000")
        FrameCodec.split(other).forEachIndexed { i, f -> collector.onFrame(f, 1100L + i) }
        val otherPf = parityFramesFor(other)
        otherPf.forEachIndexed { i, f -> collector.onFrame(f, 2000L + i) }
        // 异会话奇偶帧：拒绝计数、不入库
        collector.onFrame(pf[0], 5000L)
        assertEquals(1, collector.snapshot(5000L).rejected)
        val locked = collector.snapshot(5000L + FrameCodec.MIN_COLLECT_MS)
        assertTrue(locked.complete)
        assertEquals(other.encode(), locked.payload!!.encode())
        assertEquals(FrameCodec.sidOf(other), collector.sid)
    }

    @Test
    fun exchange_pass_recovers_dropped_frame_via_builtin_parity() {
        val p = payload()
        val sid = FrameCodec.sidOf(p)
        val segs = FrameCodec.segments(p)
        // 阶段 2 一轮序列自带奇偶帧：从中抽掉 1 个数据帧仍应完成
        val pass = FrameCodec.dataPass(sid, segs, bleInfo = null, nonce = "01020304", security = security)
        val firstData = pass.indexOfFirst { FrameCodec.parse(it)?.let { f -> !f.noise && !f.parity } == true }
        val pruned = pass.filterIndexed { i, _ -> i != firstData }
        val collector = FrameCollector()
        pruned.forEachIndexed { i, f -> collector.onFrame(f, 1000L + i) }
        val st = collector.snapshot(1000L + pruned.size + FrameCodec.MIN_COLLECT_MS)
        assertTrue(st.complete)
        assertEquals(emptyList<Int>(), st.missing)
        assertEquals(1, st.recovered)
        assertEquals(p.encode(), st.payload!!.encode())
    }
}
