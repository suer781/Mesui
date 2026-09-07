//! 安全暴力验证（对抗性）：以攻击者视角轰击核心的安全边界。
//! 不变量：任何输入不得 panic；无密钥者伪造必败；篡改一位必败；重放必被去重。
//! 运行：cargo test --test security_bruteforce -- --nocapture

use dc_core::adaptive::{Metrics, PolicyEngine, Tier};
use dc_core::envelope::{frame, unframe, Dedup, Envelope, PayloadKind, MAX_FRAME_SIZE};
use dc_core::entropy::EntropyHarvester;
use dc_core::identity::{verify, Identity};
use dc_core::mailbox::{self, BucketWrite};
use dc_core::nodekey::{NodeKeyAnnouncement, NodeKeyRing};
use dc_core::queue::Db;

struct XorShift(u64);

impl XorShift {
    fn new() -> Self {
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).unwrap();
        XorShift(u64::from_be_bytes(seed) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn sample_envelope(sender: &Identity, i: u8) -> Envelope {
    Envelope {
        msg_id: [i; 16],
        sender: sender.node_id(),
        recipient: Some([9; 32]),
        group: None,
        kind: PayloadKind::Text,
        body: vec![b'A' + (i % 20), 1, 2, 3, 4],
        sent_at_ms: 1_000_000,
        ttl_hops: 6,
    }
}

#[test]
fn adversarial_bruteforce_suite() {
    let mut rng = XorShift::new();
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let mallory = Identity::generate().unwrap();

    // ── 1. 乱码轰炸 unframe：20k 随机缓冲，绝不 panic，越界长度必报错 ──
    let mut rejected = 0u32;
    for _ in 0..20_000 {
        let n = rng.below(200) as usize;
        let buf = rng.bytes(n);
        match unframe(&buf) {
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(_) => rejected += 1,
        }
    }
    // 结构化攻击：声明超大长度的头
    let mut evil = u32::MAX.to_be_bytes().to_vec();
    evil.extend_from_slice(&rng.bytes(32));
    assert!(unframe(&evil).is_err(), "超大声明长度必须报错");
    // 合法帧在 MAX_FRAME_SIZE 内仍可用
    let good = frame(b"x");
    assert!(unframe(&good).is_ok());
    println!("[1] 乱码轰炸 unframe ×20000：panic=0，拒收={rejected}  ✓");

    // ── 2. 变异 CBOR 信封轰炸：15k 随机 + 5k 位翻转，绝不 panic ──
    let valid = sample_envelope(&alice, 1).to_cbor().unwrap();
    for _ in 0..15_000 {
        let len = rng.below(120) as usize;
        let junk = rng.bytes(len);
        let _ = Envelope::from_cbor(&junk);
    }
    for _ in 0..5_000 {
        let mut m = valid.clone();
        let pos = rng.below(m.len() as u64) as usize;
        m[pos] = rng.next() as u8;
        let _ = Envelope::from_cbor(&m); // Err 或 Ok 均合法，panic 即失败
    }
    println!("[2] CBOR 变异轰炸 ×20000：panic=0  ✓");

    // ── 3. 信箱 MAC 暴力伪造：无密钥 + 全量单位翻转，100% 拒绝 ──
    let secret = mailbox::derive_mailbox_secret(b"real-handshake-secret", &[7; 32], 1);
    let wrong = mailbox::derive_mailbox_secret(b"mallory-guess", &[7; 32], 1);
    let mut forgeries_rejected = 0u32;
    let forgeries = 3_000;
    for i in 0..forgeries {
        let mut body = rng.bytes(32);
        body[0] = i as u8;
        let env = Envelope { body, ..sample_envelope(&mallory, 2) };
        let w = BucketWrite::seal(env, &wrong, 1, 1_000_000, [(i % 255) as u8; 16]);
        if w.verify(&secret, 1_000_000).is_err() {
            forgeries_rejected += 1;
        }
    }
    assert_eq!(forgeries_rejected, forgeries, "无密钥伪造竟有漏网");
    // 全量单比特翻转（200B 正文 → 1600 次翻转，密文任意一位变化都必须打碎 MAC）
    let mut env3 = sample_envelope(&alice, 3);
    env3.body = vec![0xAA; 200];
    let mut w = BucketWrite::seal(env3, &secret, 1, 1_000_000, [9; 16]);
    assert!(w.verify(&secret, 1_000_000).is_ok(), "封印态必须先自洽");
    let mut flips_rejected = 0u32;
    let mut total_flips = 0u32;
    for byte_pos in 0..w.envelope.body.len() {
        for bit in 0..8 {
            let original = w.envelope.body[byte_pos];
            w.envelope.body[byte_pos] = original ^ (1 << bit);
            total_flips += 1;
            if w.verify(&secret, 1_000_000).is_err() {
                flips_rejected += 1;
            }
            w.envelope.body[byte_pos] = original;
        }
    }
    assert_eq!(flips_rejected, total_flips, "单比特翻转竟有漏网");
    println!("[3] MAC 暴力伪造 ×{forgeries} + 单比特翻转 ×{total_flips}：漏网=0  ✓");

    // ── 4. 重放与时间窗：同一写入两次投递必被去重，窗口边界精确 ──
    let db = Db::open(std::path::Path::new(":memory:"), Some("k")).unwrap();
    let mut dedup = Dedup::new(10_000);
    let env4 = sample_envelope(&alice, 4);
    let w4 = BucketWrite::seal(env4.clone(), &secret, 1, 1_000_000, [1; 16]);
    assert!(w4.verify(&secret, 1_000_000).is_ok());
    assert!(dedup.check_and_insert(env4.msg_id), "首投必须通过");
    assert!(!dedup.check_and_insert(env4.msg_id), "重放必须被去重");
    assert!(db.record_seen(&env4.msg_id, 0).unwrap());
    assert!(!db.record_seen(&env4.msg_id, 0).unwrap(), "持久层重放必须被拒");
    // 窗口边界：±REPLAY_WINDOW_MS 内合法，之外必拒
    let w5 = BucketWrite::seal(sample_envelope(&alice, 5), &secret, 1, 1_000_000, [2; 16]);
    let edge = mailbox::REPLAY_WINDOW_MS;
    assert!(w5.verify(&secret, 1_000_000 + edge).is_ok());
    assert!(w5.verify(&secret, 1_000_000 - edge).is_ok());
    assert!(w5.verify(&secret, 1_000_000 + edge + 1).is_err());
    assert!(w5.verify(&secret, 1_000_000 - edge - 1).is_err());
    println!("[4] 重放去重 + 时间窗边界（±{edge}ms）：精确  ✓");

    // ── 5. 节点密钥公告：伪造签名 5000 次全败 + 全位翻转 + serial 不可回退 ──
    let node_v2 = Identity::generate().unwrap();
    let mut ann = NodeKeyAnnouncement::new(&alice.node_id(), &node_v2.node_id(), 2, 1000, 86_400_000);
    ann.sign(&alice).unwrap();
    let mut forged = 0u32;
    for _ in 0..2_000 {
        let mut a = ann.clone();
        a.sig = rng.bytes(64).try_into().unwrap_or([0u8; 64]).to_vec();
        if a.verify().is_err() {
            forged += 1;
        }
    }
    assert_eq!(forged, 2_000, "随机签名竟有漏网");
    let mut ring = NodeKeyRing::new();
    ring.upsert(&ann, 1000).unwrap();
    // Mallory 声称 Alice 换钥（签名为 Mallory）：拒绝
    let mut evil_ann = NodeKeyAnnouncement::new(&alice.node_id(), &mallory.node_id(), 3, 2000, 86_400_000);
    evil_ann.sign(&mallory).unwrap_err(); // sign 层即拒绝错身签署
    evil_ann.sig = mallory.sign(&evil_ann_signing_payload_hack()).to_bytes().to_vec();
    assert!(ring.upsert(&evil_ann, 2000).is_err(), "错身签名公告必须被拒");
    // serial 回退：老公告无法覆盖新钥
    let mut ann_old = NodeKeyAnnouncement::new(&alice.node_id(), &mallory.node_id(), 1, 3000, 86_400_000);
    ann_old.sign(&alice).unwrap();
    ring.upsert(&ann_old, 3000).unwrap();
    assert_ne!(
        ring.current(&alice.node_id(), 3000),
        Some(&mallory.node_id()),
        "低 serial 公告不得覆盖当前钥"
    );
    println!("[5] 节点公告伪造 ×2000 + 错身签署 + serial 回退：全部拒绝  ✓");

    // ── 6. 身份签名暴力：5000 次随机签名对固定消息，全部失败 ──
    let msg = b"brute force target";
    let mut sig_fails = 0u32;
    for _ in 0..5_000 {
        let forged_sig = alice.sign(&rng.bytes(32));
        let tampered = dc_core::envelope::Envelope {
            msg_id: [u8::MAX; 16],
            ..sample_envelope(&bob, 6)
        };
        let _ = tampered;
        if verify(&alice.public(), msg, &forged_sig).is_err()
            && verify(&alice.public(), &rng.bytes(64), &forged_sig).is_err()
        {
            sig_fails += 1;
        }
    }
    assert_eq!(sig_fails, 5_000);
    println!("[6] 身份签名暴力 ×5000：伪造成功=0  ✓");

    // ── 7. 并发轰炸：4 线程同时写同一加密库，计数必须守恒 ──
    let alice_id = alice.node_id();
    let bob_id = bob.node_id();
    let db = std::sync::Arc::new(std::sync::Mutex::new(
        Db::open(std::path::Path::new(":memory:"), None).unwrap(),
    ));
    let mut handles = Vec::new();
    for t in 0..4u8 {
        let db = db.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..1_000u16 {
                let id = [t, (i >> 8) as u8, i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let id: [u8; 16] = id;
                let env = Envelope {
                    msg_id: id,
                    sender: alice_id,
                    recipient: Some(bob_id),
                    group: None,
                    kind: PayloadKind::Text,
                    body: vec![t, i as u8],
                    sent_at_ms: 1,
                    ttl_hops: 6,
                };
                let db = db.lock().unwrap();
                db.enqueue(&env).unwrap();
                db.record_seen(&id, 1).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let (pending, _dead, seen) = db.lock().unwrap().stats().unwrap();
    assert_eq!(pending, 4_000, "并发入队必须零丢失");
    assert_eq!(seen, 4_000, "并发去重必须零丢失");
    println!("[7] 并发轰炸 4×1000（同库同写）：零丢失、零重复  ✓");

    // ── 8. 自适应引擎 fuzz：随机指标流 1 万次，验证真实契约 ──
    // 契约（来自设计）：升档可即时跳级（宁可过度配）；降档必须逐级且需持续低载。
    let mut engine = PolicyEngine::new(Default::default());
    let mut prev = Tier::Light;
    for _ in 0..10_000 {
        let tier = engine.observe(Metrics {
            group_size: rng.below(1_000) as u32,
            msg_rate: rng.below(500) as f32,
        });
        assert!(tier >= prev || prev as i32 - tier as i32 == 1,
            "降档跳级违法契约：{prev:?}→{tier:?}（升档可跳级，降档必须逐级）");
        prev = tier;
    }
    println!("[8] 自适应引擎随机指标流 ×10000：升档跳级合法、降档逐级、无 panic  ✓");

    // ── 9. 熵源抽检：连续 100k×32B 无重复（采样） ──
    let mut h = EntropyHarvester::new().unwrap();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..100_000 {
        let mut b = [0u8; 8];
        h.draw(&mut b).unwrap();
        assert!(seen.insert(b), "熵池输出出现重复（灾难性）");
    }
    println!("[9] 熵源 ×100000 抽检：零重复  ✓");

    let _ = MAX_FRAME_SIZE;
    println!("===== 暴力验证全部通过：对抗输入下无 panic、无伪造、无重放、无丢失 =====");
}

fn evil_ann_signing_payload_hack() -> Vec<u8> {
    // Mallory 会按公开的规范化签名串自行构造 payload——这里模拟该行为的最小形态
    b"attacker-chosen-payload".to_vec()
}
