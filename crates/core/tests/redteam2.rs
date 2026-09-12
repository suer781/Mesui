//! redteam2.rs —— 第二轮红队（全新攻击视角：跨模块组合攻击）。
//!
//! 与既有套件的差别：不重复 mailbox/queue/clock 的单模块边界，专打
//! 「模块 A 单独正确、模块 B 单独正确，A+B 联动出洞」的组合。
//!
//! 断言约定（修复后状态）：本文件初版以 `red_*` 测试**断言攻击成功**
//! （漏洞诚实呈现）。7 项漏洞全部修复后，red_* 已同步改写为 `green_*`
//! **防御回归**：断言攻击失败——任何一项修复被回退，对应测试即失败。
//! 全部确定性：身份/密钥由固定种子或库内 API 生成；时钟为合成值；
//! iroh 仅环回 127.0.0.1（Node::send 返回即对端 accept 循环已跑完
//! on_message 判定，负向断言无需 sleep）。
#![cfg(all(feature = "db", feature = "signal", feature = "iroh-net"))]
#![allow(clippy::needless_range_loop)]

use dc_core::delivery::DeliveryManager;
use dc_core::envelope::{Envelope, PayloadKind};
use dc_core::handshake::Device;
use dc_core::identity::Identity;
use dc_core::maildrop::{BucketStorage, InMemoryBucketStorage, MailboxError, MailboxManager};
use dc_core::mailbox::{generate_bucket_address, BucketWrite, MailboxRead};
use dc_core::node::NodeSink;
use dc_core::node::Node;
use dc_core::queue::Db;
use dc_core::signal_store::SqlSignalStore;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000_000;

fn env(msg_id: [u8; 16], sender: [u8; 32], body: Vec<u8>) -> Envelope {
    Envelope {
        msg_id,
        sender,
        recipient: Some([9; 32]),
        group: None,
        kind: PayloadKind::Text,
        body,
        sent_at_ms: NOW,
        ttl_hops: 6,
    }
}

// ══════════════════════ GREEN 6（原 RED 1）：TOFU pin 投毒被覆盖保护兜住 ══════════════════════
//
// 原 RED 1（修复前）：QR_OFFER 是 token 门禁前的明文帧，攻击者无认证灌任意多
// trusted_identities 行并抢注真实联系人名字 → 真人扫码**永久** IdentityChanged。
//
// 修复后防御（本测试断言攻击失败）：
//  a) 抢注 pin 不可静默覆盖——同名异钥的身份 upsert 未经用户确认一律拒绝
//     （signal_store::upsert_identity_confirmed，错误与协议路径同类
//     IdentityChanged）：重复 offer / 死信 UI id 混用类上层 bug / 抢注者回抢
//     都改不动 pin，灌入的惰性行互相之间也覆盖不了；
//  b) 真人被抢注**不再永久失效**——用户确认后覆盖即恢复，恢复后 PQXDH 正常、
//     抢注者的 bundle 永久进不来；
//  c) 未认证 offer 灌充的速率限制在 Kotlin 帧层（BleMesh.onJoinerQrOffer：
//     同一 name 的 processBundle 每 30 秒最多 1 次）——Rust 核心的 TOFU
//     「首次信任」保持设计（各 ghost 首扫各得一行惰性 pin，谁也覆盖不了谁）。
#[test]
fn green6_tofu_pin_squat_needs_confirmation_and_is_recoverable() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("dc-rt2-tofu-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key = "rt2-tofu-key";

    let mut victim = Device::open(&path, Some(key), "victim").unwrap();
    let store = SqlSignalStore::open(&path, Some(key)).unwrap();

    // 攻击前置（设计内，速率限制在 Kotlin 帧层执行）：TOFU 首次信任被抢注
    let mut mallory = Device::generate("bob").unwrap();
    let mallory_bundle = mallory.prekey_bundle().unwrap();
    victim
        .process_bundle(mallory.address(), &mallory_bundle)
        .expect("TOFU 首次信任（设计如此；同名重复 offer 由帧层限频）");

    // 攻击（修复前的伤害）：真人扫码被抢注的 pin 挡死
    let mut bob = Device::generate("bob").unwrap();
    let bob_bundle = bob.prekey_bundle().unwrap();
    let err = victim
        .process_bundle(bob.address(), &bob_bundle)
        .expect_err("抢注必须被识别为身份变更");
    assert!(
        matches!(err, dc_core::CoreError::IdentityChanged(ref n) if n == "bob"),
        "拒绝必须正是 IdentityChanged 类: {err:?}"
    );

    // 防御 a：抢注 pin 不可被静默覆盖——未确认的异钥覆盖一律拒绝（同类错误）
    let bob_key = bob.identity_key().unwrap();
    let squat_err = store
        .upsert_identity_confirmed("bob", 1, &bob_key, false)
        .expect_err("RED: 同名异钥的未确认覆盖被放行");
    assert!(
        matches!(squat_err, dc_core::CoreError::IdentityChanged(ref n) if n == "bob"),
        "覆盖保护必须报同类错误: {squat_err:?}"
    );
    assert!(
        !victim.is_trusted(bob.address(), &bob_key).unwrap(),
        "未确认覆盖不得生效（抢注 pin 原样保留）"
    );

    // 防御 b：用户确认后覆盖恢复——真人不再「永久」失效
    store
        .upsert_identity_confirmed("bob", 1, &bob_key, true)
        .expect("GREEN: 用户确认后必须可恢复");
    assert!(victim.is_trusted(bob.address(), &bob_key).unwrap(), "恢复后真人钥匙可信");
    assert!(
        !victim.is_trusted(bob.address(), &mallory.identity_key().unwrap()).unwrap(),
        "恢复后抢注者钥匙不可信"
    );
    victim
        .process_bundle(bob.address(), &bob_bundle)
        .expect("GREEN: 恢复后真人的 PQXDH 必须走通");
    // 抢注者想抢回 pin：未确认覆盖被挡死
    assert!(
        victim.process_bundle(mallory.address(), &mallory_bundle).is_err(),
        "GREEN: 恢复后抢注者的 bundle 必须进不来"
    );
    let _ = std::fs::remove_file(&path);
}

// ══════════════════════ GREEN 7（原 RED 2）：iroh ACK 必须真实反映应用层受理 ══════════════════════
//
// 原 RED 2（修复前）：node.rs 的 accept 循环「on_message 回调返回后立刻回
// ACK」——回调只是把载荷转交上层；Kotlin 侧在异步协程里反查联系人/解密失败
// 静默 return，而 ACK 早已发出。发送侧 DeliveryManager 收 Ok(true) → mark_sent
// → 消息永久丢失且 UI 记「已送达」。
//
// 修复后防御（本测试断言攻击失败）：
//  a) 接收端 ACK/NAK 的唯一依据 = 应用层判定（NodeSink::on_message 返回值：
//     Some(true)=受理 / Some(false)=拒收 / None=异步经 Node::ack 回执，5s 超时
//     按 NAK）；ACK 帧 = 1 字节判定 + 8 字节回执句柄回显；
//  b) 应用层拒收（联系人反查失败/解密失败路径）→ NAK → send Err →
//     DeliveryManager 记通道错误并 fail_and_reschedule——消息不丢、不假送达。
#[test]
fn green7_iroh_ack_requires_application_acceptance() {
    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Node>();
    };

    // 接收方 sink：丢弃一切并拒收（等价于联系人反查失败/解密失败/联系人已删）。
    struct DroppingSink;
    impl NodeSink for DroppingSink {
        fn on_message(&self, _: String, _: String, _: Vec<u8>) -> Option<bool> {
            Some(false) // 红队 R2-2 修复后：sink 判定 = ACK/NAK 唯一依据
        }
        fn on_ready(&self, _: String, _: String) {}
    }
    // 发送方 sink：收集到达的消息（应为空）。
    struct CollectSink(Arc<Mutex<Vec<(String, Vec<u8>)>>>);
    impl NodeSink for CollectSink {
        fn on_message(&self, from: String, _ack: String, payload: Vec<u8>) -> Option<bool> {
            self.0.lock().unwrap().push((from, payload));
            Some(true)
        }
        fn on_ready(&self, _: String, _: String) {}
    }

    fn seed(n: u8) -> [u8; 32] {
        let mut s = [n; 32];
        s[31] = n.wrapping_add(1);
        s
    }
    /// export_naddr 只含非环回地址；把首个 sockaddr 的 IP 段改写成 127.0.0.1
    /// （端口保留），得到确定性环回快照。
    fn loopback_snapshot(snap: &str) -> String {
        fn unb64(s: &str) -> Vec<u8> {
            fn rev(c: u8) -> u32 {
                match c {
                    b'A'..=b'Z' => (c - b'A') as u32,
                    b'a'..=b'z' => (c - b'a') as u32 + 26,
                    b'0'..=b'9' => (c - b'0') as u32 + 52,
                    b'-' | b'_' => 63,
                    _ => unreachable!(),
                }
            }
            let mut out = Vec::new();
            let mut acc = 0u32;
            let mut bits = 0u32;
            for &c in s.as_bytes() {
                acc = (acc << 6) | rev(c);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push(((acc >> bits) & 0xFF) as u8);
                }
            }
            out
        }
        const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        fn b64(bytes: &[u8]) -> String {
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = ((chunk[0] as u32) << 16)
                    | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
                    | (*chunk.get(2).unwrap_or(&0) as u32);
                out.push(TBL[(n >> 18) as usize & 63] as char);
                out.push(TBL[(n >> 12) as usize & 63] as char);
                if chunk.len() > 1 {
                    out.push(TBL[(n >> 6) as usize & 63] as char);
                }
                if chunk.len() > 2 {
                    out.push(TBL[n as usize & 63] as char);
                }
            }
            out
        }
        let mut id = "";
        let mut a = None;
        for pair in snap.strip_prefix("dc://node?").unwrap_or("").split('&') {
            if let Some(v) = pair.strip_prefix("id=") {
                id = v;
            }
            if let Some(v) = pair.strip_prefix("a=") {
                a = v.split(',').next().map(str::to_owned);
            }
        }
        let raw = unb64(a.as_deref().expect("export_naddr 必须含直连地址"));
        let mut lb = raw;
        if lb.len() == 6 {
            lb[0] = 127;
            lb[1] = 0;
            lb[2] = 0;
            lb[3] = 1;
        } else if lb.len() == 18 {
            for i in 0..16 {
                lb[i] = 0;
            }
            lb[15] = 1;
        } else {
            panic!("非预期 sockaddr 长度 {}", lb.len());
        }
        format!("dc://node?v=1&id={id}&a={}", b64(&lb))
    }

    let got = Arc::new(Mutex::new(Vec::new()));
    let receiver = Node::start("", &seed(2), Arc::new(DroppingSink)).expect("receiver");
    let sender = Arc::new(Node::start("", &seed(1), Arc::new(CollectSink(got.clone()))).expect("sender"));

    // 队列 → 投递管理器 → iroh 通道的完整链路：
    let naddr = loopback_snapshot(&receiver.export_naddr());
    let s2 = sender.clone();
    let dm = DeliveryManager::new(
        Db::open(std::path::Path::new(":memory:"), None).unwrap(),
        Box::new(move |e: &Envelope| {
            s2.send(&naddr, &e.body, 15_000)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }),
    );
    dm.db()
        .lock()
        .unwrap()
        .enqueue_full(&env([2; 16], [1; 32], b"you-will-not-lose-me".to_vec()))
        .unwrap();
    let rep = dm.tick(NOW + 1000).unwrap();
    // 防御判定：应用层拒收 → NAK → 通道错误重试路径，消息不丢、不假送达
    assert_eq!(rep.sent, 0, "GREEN: 应用层拒收（NAK）不得记为已送达");
    assert_eq!(rep.errored, 1, "GREEN: NAK 必须走通道错误（Err）重试路径");
    assert!(
        got.lock().unwrap().is_empty(),
        "GREEN: 接收端应用层什么都没拿到——发送侧也不得记「已送达」"
    );
    assert_eq!(
        dm.db().lock().unwrap().stats().unwrap(),
        (1, 0, 0),
        "GREEN: 消息滞留队列待重试（不再是「已出队、永不补投」）"
    );
    sender.stop();
    receiver.stop();
}

// ══════════════════════ GREEN 8（原 RED 3）：信箱重放台账可跨进程持久化 ══════════════════════
//
// 原 RED 3（修复前）：NonceCache 注释承认「跨重启持久化由调用方负责」，但
// FFI 面没有任何导出/恢复台账的 API——Android 前台服务被杀（LMK）是常态，
// 每次进程重启，±5 分钟窗内被嗅探的合法 BucketWrite 全部可原样重放一次。
//
// 修复后防御（本测试断言攻击失败）：
//  a) NonceCache::export_state / import_state + MailboxManager::export_pair_ledger
//     / import_pair_ledger（FFI: MailboxManagerHandle::export_ledger/import_ledger）
//     ——宿主层周期性落盘、启动时恢复；
//  b) 恢复后的进程对同一份窗内嗅探写入判 ReplayRejected；导入超容量 fail-closed。
#[test]
fn green8_mailbox_replay_ledger_survives_process_restart() {
    let secret = Box::leak(Box::new([7u8; 32]));
    let sender = Identity::from_seed([9; 32]);
    let w = BucketWrite::seal(
        env([3; 16], sender.node_id(), vec![0xAB; 64]),
        secret,
        1,
        NOW,
        [5; 16],
    );

    // 进程 #1：验收通过 + 台账持久化（NodeService 周期 export → 落盘）
    let mut proc1 = MailboxManager::new(4096);
    proc1.submit_write(&w, secret, NOW).expect("首交必须通过");
    // 同进程重放被拒（防御在）
    assert_eq!(
        proc1.submit_write(&w, secret, NOW),
        Err(MailboxError::ReplayRejected),
        "同进程重放必须被拒"
    );
    let saved = proc1.export_pair_ledger(secret);
    assert_eq!(saved.len(), 1, "GREEN: 台账必须可导出（此前无任何持久化 API）");
    assert_eq!(saved[0].0, [3; 16], "导出条目 = (msg_id, expiry_ms)");
    drop(proc1); // NodeService 被杀 / 进程重启

    // 进程 #2：启动时从持久层恢复台账 → 同一份窗内嗅探写入原样重放被拒。
    let mut proc2 = MailboxManager::new(4096);
    assert_eq!(proc2.nonce_cache_len(), 0, "新进程台账为空（漏洞前提）");
    proc2.import_pair_ledger(secret, saved);
    assert_eq!(
        proc2.submit_write(&w, secret, NOW),
        Err(MailboxError::ReplayRejected),
        "GREEN: 台账持久化后，进程重启不能复活窗内重放"
    );

    // 恢复语义：导入超容量按序 fail-closed；未恢复的对不受影响
    let other_secret = Box::leak(Box::new([8u8; 32]));
    let w_other = BucketWrite::seal(
        env([4; 16], sender.node_id(), vec![0xCD; 64]),
        other_secret,
        1,
        NOW,
        [6; 16],
    );
    let mut small = MailboxManager::new(64); // 台账下限钳到 64
    small.import_pair_ledger(secret, (0..100u32).map(|i| {
        let mut id = [0u8; 16];
        id[1] = i as u8;
        (id, NOW + 400_000)
    }).collect());
    assert_eq!(small.nonce_cache_len(), 64, "GREEN: 导入超容量 fail-closed（硬顶一致）");
    assert_eq!(small.submit_write(&w_other, other_secret, NOW), Ok(()), "未恢复的对正常可写");
}

// ══════════════════════ GREEN 9（原 RED 4）：读台账按桶对分区，洪泛只伤自己 ══════════════════════
//
// 原 RED 4（修复前）：maildrop::MailboxManager::read_nonces 是一把全局 FIFO
//（容量 16384）——任一持钥联系人（pair A）刷 16384 次合法读，即可把其他桶对
//（pair B）未过期的读 nonce 逐出：B 的一条被嗅探读请求随后**原样重放成功**，
// 拉回原读取之后新入库的密文（元数据新鲜度泄露 + 重复取件）。读路径无时间窗
//（设计使然）、无限速（只有写限速）→ 洪泛零成本。
//
// 修复后防御（本测试断言攻击失败）：读台账与写台账（A6）同理按桶对分区——
// 洪泛者的合法读全部记账进**自己的分区**，他对的防重放状态互不牵连。
#[test]
fn green9_read_ledger_partition_isolates_cross_pair_eviction() {
    let bucket_b = generate_bucket_address().unwrap();
    let bucket_a = generate_bucket_address().unwrap();
    let secret_b = Box::leak(Box::new(dc_core::mailbox::derive_mailbox_secret(b"red2-b", &bucket_b, 1)));
    let secret_a = Box::leak(Box::new(dc_core::mailbox::derive_mailbox_secret(b"red2-a", &bucket_a, 1)));

    let mut mgr = MailboxManager::new(4096); // 每分区读台账容量 = 16384
    let st = InMemoryBucketStorage::default();
    let sender = Identity::from_seed([8; 32]);
    // B 桶里有一条消息
    let wb = BucketWrite::seal(env([4; 16], sender.node_id(), vec![1; 32]), secret_b, 1, NOW, [1; 16]);
    st.store(&bucket_b, &wb).unwrap();

    // B 的合法读（会被攻击者嗅探）
    let read_b = MailboxRead::seal_read(bucket_b, secret_b, 0, [0xB1; 16]);
    assert_eq!(mgr.read_bucket(&read_b, secret_b, &st, NOW).unwrap().len(), 1);
    // 同请求立即重放：被拒（防御在）
    assert_eq!(
        mgr.read_bucket(&read_b, secret_b, &st, NOW),
        Err(MailboxError::ReplayRejected),
        "基线：读重放必须被拒"
    );

    // pair A 持钥洪泛：16384 次合法读——修复后全部记账进 A 自己的分区，
    // A 的读互不影响（洪泛者的「配额」只作用于他自己）
    for i in 0..16384u32 {
        let mut n = [0u8; 16];
        n[0] = (i >> 8) as u8;
        n[1] = i as u8;
        n[2] = 0xAA;
        let r = MailboxRead::seal_read(bucket_a, secret_a, 0, n);
        assert!(
            mgr.read_bucket(&r, secret_a, &st, NOW).is_ok(),
            "GREEN: 洪泛只占自己的分区，A 的第 {i} 次合法读不受影响"
        );
    }

    // 防御判定：B 的嗅探读重放仍被拒（全局 FIFO 台账下此处会复活 → Ok）
    assert_eq!(
        mgr.read_bucket(&read_b, secret_b, &st, NOW),
        Err(MailboxError::ReplayRejected),
        "GREEN: 读台账按桶对分区后，另一桶对的洪泛挤不掉本对的防重放状态"
    );
}

// ══════════════════════ GREEN 10（原 RED 5）：sent 行可清理 + revive 只复活死信 ══════════════════════
//
// 原 RED 5（修复前）：queue.rs 的 mark_sent 只改 state（行 + 密文体永久留在
// outbox 表）→ 存储无界增长；revive 对**任意** msg_id 生效（不检查
// state='dead'）→ 已送达消息可被复活成 pending → 二次投递。
//
// 修复后防御（本测试断言攻击失败）：
//  a) revive 加 state='dead' 守卫：已送达（sent）行 revive 是 no-op；
//  b) 新增 queue::prune_sent（保留 7 天，delivery::cleanup 已接线）：sent 行
//     连密文可清理、幂等；死信不受影响（走 30 天死信窗）。
#[test]
fn green10_sent_rows_prunable_and_revive_only_revives_dead() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    // 批量上限拉到 64：单拍清空全部消息（默认 16 只发 16 条）
    let dm = DeliveryManager::with_policy(db, Some(Box::new(|_| Ok(true))), Default::default(), 64);
    for i in 0..64u8 {
        dm.db()
            .lock()
            .unwrap()
            .enqueue_full(&env([i; 16], [1; 32], vec![i; 512]))
            .unwrap();
    }
    dm.tick(NOW).unwrap();
    // 全部「已发出」：pending=0
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0));

    // 防御 1：revive 一条已送达消息 = no-op（state='dead' 守卫）
    dm.db().lock().unwrap().revive(&[7; 16]).unwrap();
    assert!(
        dm.db().lock().unwrap().due_envelopes(NOW + 1, 10).unwrap().is_empty(),
        "GREEN: revive 必须只对死信生效；已送达消息不得被复活重投"
    );
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0), "sent 行保持 sent 态");

    // 防御 2：sent 行可清理（7 天保留窗，delivery::SENT_RETENTION_MS 接线在
    // DeliveryManager::cleanup）——不再永久堆积
    let day = 24 * 60 * 60 * 1000u64;
    assert_eq!(
        dm.db().lock().unwrap().prune_sent(NOW + day).unwrap(),
        64,
        "GREEN: 64 行已发送密文全部可清"
    );
    assert_eq!(dm.db().lock().unwrap().prune_sent(NOW + day).unwrap(), 0, "清理幂等");

    // 死信不受 sent 清理影响（走独立的 30 天死信窗）
    let mut e = env([100; 16], [1; 32], vec![9; 16]);
    e.sent_at_ms = NOW;
    dm.db().lock().unwrap().enqueue_full(&e).unwrap();
    let policy = dc_core::retry::RetryPolicy { max_attempts: 1, base_delay_ms: 1, max_delay_ms: 1 };
    assert!(dm.db().lock().unwrap().fail_and_reschedule(&[100; 16], &policy, NOW).unwrap());
    assert_eq!(dm.db().lock().unwrap().prune_sent(NOW + day).unwrap(), 0);
    assert_eq!(
        dm.db().lock().unwrap().stats().unwrap(),
        (0, 1, 0),
        "GREEN: 死信保留，不受 sent 清理影响"
    );
}

// ══════════════════════ GREEN 11（原 RED 6）：inbox_seen 台账硬上限 fail-closed ══════════════════════
//
// 原 RED 6（修复前）：mailbox::NonceCache 在 A7 修复后有 [64,4096] 双向钳制 +
// fail-closed；同为「收件去重台账」的 queue::inbox_seen 却**没有容量上限**——
// msg_id 是线上攻击者自选字段，任何能投递信封的路径灌 N 条异 msg_id 即 N 行
// 持久化记录，7 天保留窗内只增不减（prune_seen 只按时间、不按容量）。
//
// 修复后防御（本测试断言攻击失败）：record_seen 加硬上限
// [`dc_core::queue::INBOX_SEEN_CAP`] = 16384——满员先补裁剪窗外记录（7 天窗），
// 仍满则 fail-closed 拒收新记录：洪泛只换来拒收，不驱逐窗内去重状态。
#[test]
fn green11_inbox_seen_ledger_is_capped_fail_closed() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let day = 24 * 60 * 60 * 1000u64;
    let cap = dc_core::queue::INBOX_SEEN_CAP;
    assert_eq!(cap, 16384);

    // 1 席窗外旧记录（8 天前）：容量压力下应被补裁剪腾位
    assert!(db.record_seen(&[0xEE; 16], NOW - 8 * day).unwrap());
    // 洪灌 cap-1 条（总恰 16384 = 满员）
    let flood = cap - 1;
    for i in 0..flood {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        assert!(db.record_seen(&id, NOW + i as u64).unwrap(), "容量内必须正常入库");
    }
    assert_eq!(db.stats().unwrap().2 as u32, cap, "GREEN: 台账满员 = 硬顶 16384");

    // 满员后新 msg_id：先补裁剪窗外旧记录（8 天前那条腾位）→ 新记录放行
    assert!(
        db.record_seen(&[0xCD; 16], NOW).unwrap(),
        "GREEN: 窗外记录被补裁剪腾位，新记录放行"
    );
    assert_eq!(db.stats().unwrap().2 as u32, cap, "GREEN: 腾位后仍满员");

    // 再来新 id：真满 → fail-closed 拒收（洪泛只换来拒收，不驱逐窗内状态）
    assert!(
        !db.record_seen(&[0xCF; 16], NOW).unwrap(),
        "GREEN: 满员后新写入必须 fail-closed"
    );
    assert_eq!(db.stats().unwrap().2 as u32, cap, "GREEN: fail-closed 不改变台账");
    // 去重防线完整：首条窗内记录仍被去重拒绝（未被驱逐）
    assert!(!db.record_seen(&[0u8; 16], NOW).unwrap(), "GREEN: 窗内记录仍在，重放仍被拒");

    // 对照：同样语义的 NonceCache 有 4096 硬顶（A7 修复）
    let mut nc = dc_core::mailbox::NonceCache::new(30_000);
    let mut accepted = 0u32;
    for i in 0..30_000u32 {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        if nc.check_and_insert(&id, NOW, NOW) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 4096, "对照：NonceCache 硬顶 4096（inbox_seen 现已对齐同一 fail-closed 语义）");
}

// ══════════════════════ GREEN 12（原 RED 7）：token-MAC 绑定会话名 + 时效界 ══════════════════════
//
// 原 RED 7（修复前）：first_message_mac(token, bucket, ct) 的密钥只由 QR 载荷
// 里的 token+bucket 派生：不绑定对端名字、时间、会话序号，核心层也没有任何
// 一次性消费登记——载荷被完整拍摄（3 秒在场门槛内的截屏/录像逐帧）后，
// (token, bucket) 成为**永久握手能力**。
//
// 修复后防御（本测试断言攻击失败）：MAC 输入绑定会话名（name）+ 时效界
//（expiry_ms，出示端生成载荷时给出、随载荷分发），验证入口检查 expiry——
// 拍摄物只在窗口内、只对本次配对会话有效，不再是永久握手能力。
#[test]
fn green12_first_message_mac_bound_to_context_and_expiry() {
    let token = [0x5Au8; 48];
    let bucket = [0x3Cu8; 32];
    let ct = b"prekey-signal-message-bytes";
    let name = "bob-uuid";
    let expiry = NOW + 300_000;
    let mac = dc_core::handshake::first_message_mac(&token, &bucket, name, expiry, ct);

    // 窗口内可验（same input 恒同 MAC，确定性保留）
    dc_core::handshake::verify_first_message_mac(&token, &bucket, name, expiry, ct, &mac, NOW)
        .expect("GREEN: 窗口内必须通过");
    // 防御 1：过期即拒——拍摄物不是永久握手能力
    assert!(
        dc_core::handshake::verify_first_message_mac(&token, &bucket, name, expiry, ct, &mac, expiry + 1)
            .is_err(),
        "RED: token-MAC 过期后仍可验证（无时效界）"
    );
    // 防御 2：换会话名验证必败——重放帧不能对任意配对会话复用
    assert!(
        dc_core::handshake::verify_first_message_mac(&token, &bucket, "mallory", expiry, ct, &mac, NOW)
            .is_err(),
        "RED: token-MAC 未绑定会话名（跨会话复用）"
    );
    // name/expiry 进 MAC 输入：同 token+ct 在不同上下文下 MAC 必然不同
    assert_ne!(
        dc_core::handshake::first_message_mac(&token, &bucket, name, expiry + 1, ct),
        mac,
        "GREEN: expiry 必须进 MAC 输入"
    );
    assert_ne!(
        dc_core::handshake::first_message_mac(&token, &bucket, "other-session", expiry, ct),
        mac,
        "GREEN: name 必须进 MAC 输入"
    );
}

// ══════════════════════ GREEN：防御成立的组合 ══════════════════════

/// G1：三类 SQLCipher 库的 strict 模式一致——文件库无 key 一律拒绝
/// （密钥生命周期攻击面：不存在「静默明文」的旁路）。
#[test]
fn green1_all_file_stores_refuse_unencrypted() {
    let dir = std::env::temp_dir();
    let stamp = std::process::id();
    let p1 = dir.join(format!("dc-rt2-q-{stamp}.db"));
    let p2 = dir.join(format!("dc-rt2-s-{stamp}.db"));
    let p3 = dir.join(format!("dc-rt2-c-{stamp}.db"));
    assert!(Db::open(&p1, None).is_err());
    assert!(dc_core::signal_store::SqlSignalStore::open(&p2, None).is_err());
    assert!(dc_core::contacts::ContactStore::open(&p3, None).is_err());
    for p in [&p1, &p2, &p3] {
        let _ = std::fs::remove_file(p);
    }
}

/// G2：信封结构门禁——单播/群播互斥、群播零 TTL 拒收（跨中继组合的根校验）。
#[test]
fn green2_envelope_structural_gate() {
    let id = Identity::from_seed([1; 32]);
    let mut e = env([1; 16], id.node_id(), vec![1]);
    e.group = Some([2; 32]);
    e.recipient = Some([3; 32]);
    assert!(Envelope::from_cbor(&e.to_cbor().unwrap()).is_err(), "单播+群播必须互斥");
    e.recipient = None;
    e.ttl_hops = 0;
    assert!(Envelope::from_cbor(&e.to_cbor().unwrap()).is_err(), "群播零 TTL 必须拒收");
}

/// G3：同进程信箱门禁三类判定不互相穿透（重放 ≠ 限速 ≠ 篡改 ≠ 时钟漂移）。
#[test]
fn green3_mailbox_gate_error_classes_are_distinct() {
    let secret = Box::leak(Box::new(dc_core::mailbox::derive_mailbox_secret(b"g3", &[3; 32], 1)));
    let sender = Identity::from_seed([2; 32]);
    let mut mgr = MailboxManager::new(4096);
    let w = BucketWrite::seal(env([9; 16], sender.node_id(), vec![1; 32]), secret, 1, NOW, [9; 16]);
    mgr.submit_write(&w, secret, NOW).unwrap();
    assert_eq!(mgr.submit_write(&w, secret, NOW), Err(MailboxError::ReplayRejected));
    let mut tampered = w.clone();
    tampered.envelope.body.push(1);
    assert_eq!(mgr.submit_write(&tampered, secret, NOW), Err(MailboxError::MacMismatch));
    let late = BucketWrite::seal(env([8; 16], sender.node_id(), vec![2; 32]), secret, 1, NOW - 6 * 60_000, [8; 16]);
    assert_eq!(mgr.submit_write(&late, secret, NOW), Err(MailboxError::WindowExceeded));
}

/// G4：极端时钟输入（u64::MAX）驱动 tick 不 panic、顺序确定、不误投未到期消息。
#[test]
fn green4_delivery_survives_extreme_clock() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let dm = DeliveryManager::with_policy(db, Some(Box::new(|_| Ok(true))), Default::default(), 4);
    let mut e = env([1; 16], [1; 32], vec![1]);
    e.sent_at_ms = u64::MAX; // 钳制进 i64::MAX
    dm.db().lock().unwrap().enqueue_full(&e).unwrap();
    let rep = dm.tick(u64::MAX).unwrap(); // 不 panic
    assert_eq!(rep.sent, 1);
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0));
}

/// G5：iroh 发送入口对畸形输入 fail-closed（空载荷/超限/坏快照），不触网。
#[test]
fn green5_node_send_rejects_malformed_input() {
    struct Sink;
    impl NodeSink for Sink {
        fn on_message(&self, _: String, _: String, _: Vec<u8>) -> Option<bool> {
            Some(true)
        }
        fn on_ready(&self, _: String, _: String) {}
    }
    let n = Node::start("", &[5; 32], Arc::new(Sink)).unwrap();
    let snap = n.export_naddr();
    assert!(n.send("garbage", b"x", 1000).is_err());
    assert!(n.send(&snap, &[], 1000).is_err(), "空载荷必须拒绝");
    assert!(n.send(&snap, &vec![0u8; 256 * 1024 + 1], 1000).is_err(), "超限载荷必须拒绝");
    n.stop();
}
