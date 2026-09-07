//! 红队攻击套件（redteam.rs）：覆盖 security_bruteforce.rs 未覆盖的攻击面——
//! 跨调用状态机序列、整数边界、缓存驱逐链与逻辑组合攻击。
//!
//! 断言约定：每个测试断言「攻击必须失败 / 系统必须存活」。
//! 测试失败 = 攻击成功 = 真实漏洞；通过 = 系统扛住该类攻击。
//! 全部确定性：身份一律 from_seed，无 sleep、无真实时钟依赖。
//!
//! 攻击序列中「重复推送同一票据/同一输入」是重放攻击的本体形态，属故意写法：
#![allow(clippy::same_item_push, clippy::vec_init_then_push)]

use dc_core::adaptive::{Metrics, PolicyEngine, Tier};
use dc_core::clock::InternalClock;
use dc_core::envelope::{frame, unframe, Dedup, Envelope, PayloadKind};
use dc_core::governor::{RelayGovernor, STRANGER_SHARE_FLOOR};
use dc_core::identity::Identity;
use dc_core::mailbox::{derive_mailbox_secret, verify_inbound, BucketWrite, NonceCache};
use dc_core::nodekey::{NodeKeyAnnouncement, NodeKeyRing, DEFAULT_OVERLAP_MS};
use dc_core::queue::Db;
use dc_core::relay::{RelayGuard, RelayTicket, MAX_TICKET_TTL_MS};
use dc_core::retry::RetryPolicy;

const NOW: u64 = 1_700_000_000_000;

fn env_from(sender: [u8; 32], i: u8) -> Envelope {
    Envelope {
        msg_id: [i; 16],
        sender,
        recipient: Some([9; 32]),
        group: None,
        kind: PayloadKind::Text,
        body: vec![b'A' + (i % 20), 1, 2, 3, 4],
        sent_at_ms: NOW,
        ttl_hops: 6,
    }
}

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

/// 静默 panic 钩子（仅用于「必须不 panic」的判定，不污染其他测试输出）。
fn quiet_panic<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    r
}

// ════════════════════════════ 缓存驱逐链 ════════════════════════════

/// NonceCache 驱逐重放：nonce 缓存是 RAM 内 FIFO 有界队列。
/// 攻击者只需窃听合法流量：合法发送者在一个 ±5min 重放窗内发出 cap+1 条消息，
/// 最旧 nonce 被挤出，随后原样重放最旧那条合法写入 → MAC 对、窗口对、nonce 已被
/// 驱逐 → verify_inbound 全流程放行，同一条消息被投递两次。
#[test]
fn red1_nonce_cache_fifo_eviction_replay() {
    let secret = derive_mailbox_secret(b"redteam-r1", &[7; 32], 1);
    let mut nonces = NonceCache::new(4); // 调用方选小容量（移动端常见取舍）
    let mut writes = Vec::new();
    for i in 0..6u8 {
        writes.push(BucketWrite::seal(env_from([1; 32], i), &secret, 1, NOW, [i; 16]));
    }
    // 合法发送者的 6 条消息在窗口内依次到达，全部通过（前 2 条 nonce 已被 FIFO 挤出）
    for w in &writes {
        verify_inbound(w, &secret, &mut nonces, NOW).expect("合法写入必须通过");
    }
    // 攻击者重放第 0 条（窗内嗅探的合法写入）：nonce 已被驱逐 → 必须仍然拒绝
    assert!(
        verify_inbound(&writes[0], &secret, &mut nonces, NOW).is_err(),
        "RED: FIFO 驱逐让窗内重放复活——有界 RAM nonce 缓存不能作为唯一重放防线"
    );
}

/// RelayGuard 多来源驱逐重放：单来源灌票挤不掉活票（每来源限 4 槽），
/// 但攻击者拥有无限密钥对：用 N 个不同来源各签 1 张
/// 「满 TTL(2h)」票，而全局逐出策略踢「最快过期」——合法活票（剩余寿命短）
/// 永远先被踢。max_entries=8 配置即可击穿。
#[test]
fn red2_relay_guard_multi_origin_eviction_replay() {
    let challenge = [0xAA; 32];
    let victim = identity(0x01);
    let dest = identity(0x02);
    let mut live = RelayTicket::new(
        &dest.node_id(),
        &victim.node_id(),
        NOW,
        NOW + 30 * 60_000, // 合法票：剩余寿命 30min（全局最快过期）
        [1; 16],
        challenge,
    );
    live.sign(&victim).unwrap();
    let mut guard = RelayGuard::new(8); // 与 cache_flood 测试同配置
    assert!(guard.accept(&live, NOW, challenge), "活票首次必须接受");
    assert!(!guard.accept(&live, NOW, challenge), "基线：同票立即重放必须拒绝");

    // 攻击者：8 个不同来源（每来源仅占 1 槽 < 4 限占），每张票剩余寿命 2h（远长于活票）
    for i in 0..8u8 {
        let origin = identity(0x80 + i);
        let mut t = RelayTicket::new(
            &dest.node_id(),
            &origin.node_id(),
            NOW,
            NOW + MAX_TICKET_TTL_MS - i as u64, // 互异且全部晚于活票过期
            [0x20 + i; 16],
            challenge, // 攻击者与中继自己握手即拿到合法挑战
        );
        t.sign(&origin).unwrap();
        // 修复后（fail-closed）：活条目占满后拒绝新票——第 8 张攻击票被拒。
        // 攻击者换来「新票暂不可入」（≤2h 自然排空），换不来「已收票的重放丢失」
        if i < 7 {
            assert!(guard.accept(&t, NOW, challenge), "攻击票本身是合法签名票");
        } else {
            assert!(!guard.accept(&t, NOW, challenge), "缓存满后 fail-closed 拒新");
        }
    }
    // 全局逐出已废除：活票的防重放指纹绝不被清 → 重放复活不再可能
    assert!(
        !guard.accept(&live, NOW + 1_000, challenge),
        "修复后：多来源灌票无法清掉活票防重放状态，同票二次转发依然被拒"
    );
}

/// 票 issued_at 现已校验（not_before 语义）——
/// 未来签发的票在 verify 层即被拒，无法占据槽位，也无法复活重放。
#[test]
fn red3_future_issued_ticket_rejected_at_verify() {
    let challenge = [0xBB; 32];
    let dest = identity(0x03);
    let mut guard = RelayGuard::new(8);
    let century_ms = 100u64 * 365 * 24 * 3600 * 1000;
    for i in 0..8u8 {
        let origin = identity(0x90 + i);
        let mut t = RelayTicket::new(
            &dest.node_id(),
            &origin.node_id(),
            NOW + century_ms,             // 未来 99 年签发
            NOW + century_ms + 3_600_000, // TTL 1h ≤ 2h 上限
            [0x40 + i; 16],
            challenge,
        );
        t.sign(&origin).unwrap();
        assert!(t.verify(NOW, challenge).is_err(), "未来票必须在 verify 层被拒");
        assert!(!guard.accept(&t, NOW, challenge), "未来票不得入环");
    }
    // 合法票不受影响
    let honest = identity(0x04);
    let mut legit = RelayTicket::new(
        &dest.node_id(),
        &honest.node_id(),
        NOW,
        NOW + 3_600_000,
        [0x50; 16],
        challenge,
    );
    legit.sign(&honest).unwrap();
    assert!(guard.accept(&legit, NOW, challenge), "合法票正常入环");
}

// ════════════════════════════ 时钟整数边界 ════════════════════════════

/// restore_high_water 未校验 u64::MAX → 回滚钳制返回 -1：
/// 高水位从持久层恢复（崩溃恢复路径），无任何上界校验。
/// 恢复 u64::MAX 后触发回滚检测时，`internal_high_water_ms as i64` 回绕成 -1：
/// 「安全时钟」返回负值；调用方 cast 回 u64 即 u64::MAX → mailbox.verify 判一切
/// 过旧而全拒（DoS），queue 的 now+delay 溢出，record_seen 存负值——
/// 一处未校验输入污染整条时间安全链。
#[test]
fn red4_clock_restore_high_water_wrap_negative() {
    let mut c = InternalClock::new();
    c.restore_high_water(u64::MAX); // 持久层被篡改/损坏后的恢复输入
    let _ = c.now(10_000_000); // 本地钟正常前进，建立本地高水位
    let pinned = c.now(9_000_000); // 系统钟回拨 1000s（>1min）→ 回滚保护接管
    assert!(pinned > 0, "RED: 回滚钳制返回负值 {pinned}（u64::MAX as i64 回绕），安全时钟输出毒化");
    assert!(c.high_water_ms() < u64::MAX, "RED: 高水位被未校验持久值污染并会被再次持久化");
}

/// on_network_sync 减法溢出 panic：raw = network_ms - local_ms 是裸 i64
/// 减法。网络时间源（NTP 无认证，报文字段攻击者可控）给出 i64::MAX，
/// 系统钟被设到 1970 前（负 local_ms）→ debug 构建直接 panic = 远程可触发的崩溃。
#[test]
fn red5_clock_network_sync_overflow_panic() {
    let mut c = InternalClock::new();
    let r = quiet_panic(|| {
        c.on_network_sync(1, -3_000_000_000_000, i64::MAX); // 1968 年的钟 + 极端 NTP 响应
    });
    assert!(r.is_ok(), "RED: on_network_sync 对极端 i64 输入 panic（减法溢出未用 saturating）");
}

/// 双源一致回拨 → ±5min 重放窗实际变为 ±24h：双源交叉验证只防
/// 「单源」，两个未认证 NTP 源在同一路径上同样报 -20min 即达成一致并采纳。
/// 回拨后，20 分钟前嗅探的合法写入重新落入 ±5min 窗口 → 重放复活。
#[test]
fn red6_clock_backward_shift_revives_old_writes() {
    let secret = derive_mailbox_secret(b"redteam-r6", &[7; 32], 1);
    let old_ts = NOW - 20 * 60_000; // 20 分钟前的合法写入
    let old_write = BucketWrite::seal(env_from([1; 32], 7), &secret, 1, old_ts, [0x61; 16]);
    assert!(old_write.verify(&secret, NOW).is_err(), "基线：正常时钟下 20 分钟前写入必须被拒");

    // 攻击者控制同一路径上的两个时间源（如未认证 NTP ×2），一致回拨 20 分钟
    let mut c = InternalClock::new();
    c.on_network_sync(1, NOW as i64, NOW as i64 - 20 * 60_000);
    c.on_network_sync(2, NOW as i64, NOW as i64 - 20 * 60_000);
    let poisoned_now = c.now(NOW as i64) as u64;

    assert!(
        old_write.verify(&secret, poisoned_now).is_err(),
        "RED: 被回拨的内部钟复活了 20 分钟前的写入（重放窗应与偏移解耦）"
    );
    let mut nonces = NonceCache::new(100);
    assert!(
        verify_inbound(&old_write, &secret, &mut nonces, poisoned_now).is_err(),
        "RED: 官方入站流程完整放行了旧写入重放"
    );
}

// ════════════════════════════ 队列整数边界 ════════════════════════════

/// record_seen 的 u64→i64 铸造 + 例行裁剪 = 去重蒸发：
/// now_ms=u64::MAX（毒化时钟的下游产物）经 `as i64` 存成 seen_ms=-1；
/// 下一次例行 prune_seen(0)（「保留全部正常时间戳」）按 seen_ms<0 把它删掉，
/// 同一 msg_id 立即可被再次接受 = 持久层重放防线失效。
#[test]
fn red7_queue_seen_ms_negative_prune_replay() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let id = [0x71u8; 16];
    assert!(db.record_seen(&id, u64::MAX).unwrap(), "首次记录必须成功");
    db.prune_seen(0).unwrap(); // 例行裁剪：before=0 意图是「什么都不删」
    assert!(
        !db.record_seen(&id, 0).unwrap(),
        "RED: 负 seen_ms 行被 prune 静默删除，同一消息被持久层二次接受"
    );
}

/// fail_and_reschedule 的 now_ms+delay u64 溢出 panic：
/// `(now_ms + delay) as i64` 是裸 u64 加法。now_ms 来自毒化时钟链
/// （-1 cast 回 u64::MAX）时 debug 构建 panic = 状态机线程崩溃。
#[test]
fn red8_queue_fail_reschedule_u64_overflow_panic() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    db.enqueue(&env_from([1; 32], 1)).unwrap();
    let policy = RetryPolicy::default();
    let r = quiet_panic(|| db.fail_and_reschedule(&[0x81u8; 16], &policy, u64::MAX));
    // 真实入队的行（msg_id 与查询一致）：attempts<max → 走到 (now_ms+delay) 溢出点
    let db2 = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let id = [0x82u8; 16];
    let mut e = env_from([1; 32], 2);
    e.msg_id = id;
    db2.enqueue(&e).unwrap();
    let r2 = quiet_panic(|| db2.fail_and_reschedule(&id, &policy, u64::MAX));
    assert!(r.is_ok() && r2.is_ok(), "RED: now_ms=u64::MAX 时 fail_and_reschedule 溢出 panic（now+delay 未用 saturating_add）");
}

/// sent_at_ms = u64::MAX → created_ms = -1 → 队列插队：
/// enqueue 把攻击者可控的 sent_at_ms 直接 `as i64` 存为排序键 created_ms。
/// u64::MAX 回绕成 -1，ORDER BY created_ms 让它排到全部合法消息之前：
/// 任何把外来信封转投出站队列的路径（人群转发逐跳重投）都会被攻击者插队，
/// 正规消息被无限挤后 = 优先级反转 DoS。
#[test]
fn red9_queue_sent_at_priority_inversion() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let mut evil = env_from([1; 32], 2);
    evil.sent_at_ms = u64::MAX; // 攻击者注入的时间戳
    let mut legit = env_from([1; 32], 1);
    legit.sent_at_ms = NOW;
    db.enqueue(&evil).unwrap(); // 攻击者消息先到
    db.enqueue(&legit).unwrap(); // 正规消息后到
    let rows = db.pending(2).unwrap();
    assert_eq!(
        rows[0].msg_id,
        [1; 16],
        "RED: sent_at_ms=u64::MAX 回绕为 -1 抢占队首，投递顺序背离到达序"
    );
}

// ════════════════════════════ 无界状态 ════════════════════════════

/// NodeKeyRing 无容量上限：upsert 只按过期淘汰（30 天窗），
/// 单身份条目数无上限。任何一个恶意/失窃联系人都能用自己的长期钥连续签发
/// 「serial 递增、30 天有效」的合法公告——签名全绿、全部入环、内存无界增长。
/// MAX_VALIDITY_MS 限制了单条公告寿命，却没限制条数（防「百年公告」没防「百万公告」）。
#[test]
fn red10_nodekey_ring_unbounded_growth() {
    let peer = identity(0x0A); // 恶意联系人：签名永远合法
    let mut ring = NodeKeyRing::new();
    for s in 1..=5_000u64 {
        let node = Identity::from_seed([(s % 251) as u8 + 1; 32]).node_id();
        let mut ann = NodeKeyAnnouncement::new(&peer.node_id(), &node, s, NOW, DEFAULT_OVERLAP_MS);
        ann.sign(&peer).unwrap();
        ring.upsert(&ann, NOW).expect("签名合法的公告必须入环");
    }
    assert!(
        ring.state().len() <= 64,
        "RED: 单身份 {} 条公告全部驻留——无容量上限，联系人可无界膨胀内存",
        ring.state().len()
    );
}

/// NaN 指标绕过负载治理：governor.set_load(NaN) 经 clamp 原样传播，
/// load_share 两个比较分支全 false 落入 smoothstep(NaN)=NaN，f64::min 丢弃 NaN
/// → 按「满载 15%」放行；adaptive 的 msg_rate=NaN 同理使 demanded 永远 Light。
/// 喂入侧一旦出现 0/0（除零 bug 或被污染的指标通道），降档与升档同时失明。
#[test]
fn red11_nan_metrics_bypass_load_governance() {
    let mut g = RelayGovernor::new(120);
    g.set_load(f32::NAN);
    assert!(
        g.share() <= STRANGER_SHARE_FLOOR + 1e-9,
        "RED: NaN 负载按满份额 {} 放行（应按最坏情况落在地板）",
        g.share()
    );
    let mut e = PolicyEngine::new(Default::default());
    let tier = e.observe(Metrics { group_size: 0, msg_rate: f32::NAN });
    assert_eq!(
        tier,
        Tier::Heavy,
        "RED: NaN 速率被当成零载（fail-open），洪峰下引擎永远不升档"
    );
}

/// CBOR 无界递归：未知字段值是深嵌套不定长数组，ciborium 反序列化
/// IgnoredAny 逐层递归。≤120 字节的随机片 fuzz 覆盖不到——递归深度攻击需要
/// 特构的深层嵌套结构。断言：必须返回 Err 而不是打爆栈（stack overflow 会
/// abort 整个进程，不可捕获）。
#[test]
fn red12_cbor_deep_nesting_must_not_crash() {
    let depth = 100_000usize;
    let mut b = Vec::with_capacity(2 * depth + 3);
    b.push(0xA1); // map(1)
    b.push(0x61);
    b.push(b'q'); // key "q"：Envelope 无此字段 → IgnoredAny
    for _ in 0..depth {
        b.push(0x9F); // 不定长数组嵌套
    }
    for _ in 0..depth {
        b.push(0xFF); // break
    }
    let r = dc_core::envelope::Envelope::from_cbor(&b);
    assert!(r.is_err(), "RED: 深嵌套 CBOR 必须被深度限制拒绝而非递归消化");
    println!("[red12] depth=100k → {:?}", r.err());

    // 更深（1M 层，2MB 输入）也不得打爆栈
    let depth = 1_000_000usize;
    let mut b2 = Vec::with_capacity(2 * depth + 3);
    b2.push(0xA1);
    b2.push(0x61);
    b2.push(b'q');
    for _ in 0..depth {
        b2.push(0x9F);
    }
    for _ in 0..depth {
        b2.push(0xFF);
    }
    assert!(
        dc_core::envelope::Envelope::from_cbor(&b2).is_err(),
        "RED: 1M 层嵌套必须被拒绝而非栈溢出 abort"
    );
    // 嵌套体出现在「合法字段内部」也一样：body 是 byte string 不递归，
    // 但 sender/group 等 32B 字段位置喂数组同样不得 panic
    let mut b3 = Vec::new();
    b3.push(0xA1); // map(1)
    b3.push(0x61);
    b3.push(b's'); // "s" → sender 期望 32 字节
    b3.push(0x9F); // 给它一个不定长数组
    b3.push(0xFF);
    let _ = dc_core::envelope::Envelope::from_cbor(&b3);
}

// ════════════════════════════ 系统扛住的攻击面 ════════════════════════════

/// 票窗形状完备性：TTL 上限对 issued/expiry 的极端摆位全部成立。
#[test]
fn green1_relay_ticket_window_shapes_rejected() {
    let origin = identity(0x0B);
    let dest = identity(0x0C);
    let mk = |issued: u64, expiry: u64, nonce: [u8; 16]| {
        let mut t = RelayTicket::new(&dest.node_id(), &origin.node_id(), issued, expiry, nonce, [1; 32]);
        t.sign(&origin).unwrap();
        t
    };
    assert!(mk(NOW, NOW + MAX_TICKET_TTL_MS + 1, [1; 16]).verify(NOW, [1; 32]).is_err(), "TTL 超上限必拒");
    assert!(mk(0, 3_600_000, [2; 16]).verify(NOW, [1; 32]).is_err(), "远古票必拒");
    // 未来签发（issued > now+2min 偏移）在 verify 层被拒——
    // NOW+1h 签发 > NOW+2min 容差 → 拒（旧版接受是漏洞前提）
    assert!(mk(NOW + 3_600_000, NOW + 3_600_000, [3; 16]).verify(NOW, [1; 32]).is_err(), "未来签发必拒");
    assert!(mk(NOW, NOW + 3_600_000, [4; 16]).verify(NOW, [1; 32]).is_ok(), "正常票必须通过");
}

/// RelayGuard 零容量不挂死：容量 0 被钳到 1，逐出循环有界。
#[test]
fn green2_relay_guard_zero_capacity_bounded() {
    let origin = identity(0x0D);
    let dest = identity(0x0E);
    let mk = |nonce: [u8; 16]| {
        let mut t = RelayTicket::new(&dest.node_id(), &origin.node_id(), NOW, NOW + 3_600_000, nonce, [1; 32]);
        t.sign(&origin).unwrap();
        t
    };
    let mut guard = RelayGuard::new(0);
    assert!(guard.accept(&mk([1; 16]), NOW, [1; 32]));
    // fail-closed 语义：容量 1 已被活条目占满，且条目与当前
    // 挑战同纪元（不可逐出）→ 后续新票一律拒绝，直到原条目过期（≤2h+偏移）。
    // 这是有意的权衡：防重放完整性 > 新票可用性。
    assert!(!guard.accept(&mk([2; 16]), NOW, [1; 32]));
    // 同指纹重放同样被拒（条目仍在缓存中）
    assert!(!guard.accept(&mk([1; 16]), NOW, [1; 32]));
}

/// 未注册陌生发送者默认拒绝。
#[test]
fn green3_governor_unregistered_sender_denied() {
    let mut g = RelayGovernor::new(120);
    let stranger = [0x0Fu8; 32];
    assert!(!g.allow_send(&stranger, 1000));
    assert!(!g.allow_recv(&stranger, 1000));
}

/// 信封极端字段存活：u64::MAX 时间戳、None/Some 组合、64KB body。
#[test]
fn green4_envelope_extreme_fields_survive() {
    let e = Envelope {
        msg_id: [u8::MAX; 16],
        sender: [u8::MAX; 32],
        recipient: None,
        group: Some([7; 32]),
        kind: PayloadKind::GroupMgmt,
        body: vec![0xAB; 65_536],
        sent_at_ms: u64::MAX,
        ttl_hops: 255,
    };
    let cbor = e.to_cbor().unwrap();
    assert_eq!(Envelope::from_cbor(&cbor).unwrap(), e);
    let f = frame(&cbor);
    assert!(unframe(&f[..4 + 10]).unwrap().is_none());
    let (payload, consumed) = unframe(&f).unwrap().unwrap();
    assert_eq!(consumed, f.len());
    assert_eq!(Envelope::from_cbor(payload).unwrap(), e);
}

/// serial u64::MAX 单调性：顶格 serial 之后任何低 serial 无法回退。
#[test]
fn green5_nodekey_serial_u64max_monotonic() {
    let peer = identity(0x10);
    let node_new = identity(0x11).node_id();
    let mut a = NodeKeyAnnouncement::new(&peer.node_id(), &node_new, u64::MAX, NOW, DEFAULT_OVERLAP_MS);
    a.sign(&peer).unwrap();
    let mut ring = NodeKeyRing::new();
    ring.upsert(&a, NOW).unwrap();
    let node_low = identity(0x12).node_id();
    let mut low = NodeKeyAnnouncement::new(&peer.node_id(), &node_low, 1, NOW, DEFAULT_OVERLAP_MS);
    low.sign(&peer).unwrap();
    ring.upsert(&low, NOW).unwrap(); // 乱序低 serial：静默丢弃
    assert_eq!(ring.current(&peer.node_id(), NOW + 1000), Some(&node_new));
    assert!(!ring.accepts(&peer.node_id(), &node_low, NOW + 1000));
}

/// Dedup 容量 0 仍去重。
#[test]
fn green6_dedup_zero_capacity_still_dedups() {
    let mut d = Dedup::new(0);
    assert!(d.check_and_insert([1; 16]));
    assert!(!d.check_and_insert([1; 16]));
    assert!(d.check_and_insert([2; 16]));
    assert_eq!(d.len(), 1);
}

/// 库文件真实加密 + PRAGMA key 注入转义：
/// 文件头不得是明文 SQLite 魔数；单引号形态的 key 必须按字面量处理。
#[test]
fn green7_db_file_actually_encrypted_and_key_injection_escaped() {
    let dir = std::env::temp_dir().join(format!("dc-redteam-g7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("enc.db");
    {
        let db = Db::open(&path, Some("right-key-123")).unwrap();
        db.enqueue(&env_from([1; 32], 1)).unwrap();
    }
    let header = std::fs::read(&path).unwrap();
    assert!(header.len() > 16, "库文件必须有内容");
    assert_ne!(
        &header[..16],
        b"SQLite format 3\0",
        "库文件头是明文 SQLite 魔数——整库加密未生效"
    );
    assert!(Db::open(&path, Some("wrong-key")).is_err(), "错误密钥必须打不开库");
    // SQL 注入形态的 key
    let path2 = dir.join("inj.db");
    let evil_key = "x'; ATTACH DATABASE 'evil.db' AS evil; --";
    {
        let db = Db::open(&path2, Some(evil_key)).unwrap();
        db.enqueue(&env_from([1; 32], 2)).unwrap();
    }
    {
        let db = Db::open(&path2, Some(evil_key)).unwrap();
        assert_eq!(db.stats().unwrap().0, 1, "注入形态密钥必须按字面量处理且可读回");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 坏 MAC 轰炸不得污染 nonce 缓存：MAC 门在 nonce 消耗之前，
/// 攻击者不能用同 nonce 的坏 MAC 写入预先耗尽合法写入的重放配额。
#[test]
fn green8_bad_mac_does_not_pollute_nonce_cache() {
    let secret = derive_mailbox_secret(b"redteam-g8", &[7; 32], 1);
    let mut nonces = NonceCache::new(1000);
    let w = BucketWrite::seal(env_from([1; 32], 1), &secret, 1, NOW, [5; 16]);
    for i in 0..1000u16 {
        let mut bad = w.clone();
        bad.mac = [(i % 256) as u8; 32];
        assert!(verify_inbound(&bad, &secret, &mut nonces, NOW).is_err());
    }
    assert!(
        verify_inbound(&w, &secret, &mut nonces, NOW).is_ok(),
        "合法写入必须不受坏 MAC 轰炸影响"
    );
}
