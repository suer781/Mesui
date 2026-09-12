//! redteam2.rs —— 第二轮红队（全新攻击视角：跨模块组合攻击）。
//!
//! 与既有套件的差别：不重复 mailbox/queue/clock 的单模块边界，专打
//! 「模块 A 单独正确、模块 B 单独正确，A+B 联动出洞」的组合。
//!
//! 断言约定（与旧套件相反，务必注意）：
//! - `red_*` 测试 **断言攻击成功**：测试通过 = 漏洞真实存在（诚实呈现）。
//! - `green_*` 测试断言防御成立：通过 = 该组合攻击被扛住。
//! 全部确定性：身份/密钥由固定种子或库内 API 生成；时钟为合成值；
//! iroh 仅环回 127.0.0.1（Node::send 返回即对端 accept 循环已跑完
//! on_message，负向断言无需 sleep）。
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

// ══════════════════════ RED 1：TOFU pin 投毒（配对传输 × signal_store） ══════════════════════
//
// 组合：Kotlin 侧 QR_OFFER（蓝牙明文帧）在**任何 token/时长门禁之前**就调用
// Device::process_bundle（BleMesh::onJoinerQrOffer）→ signal_store 的 TOFU
// 「无记录 = 信任」。两个模块各自「正确」：QR_OFFER 携带的本就是公开
// PreKeyBundle；TOFU 首次信任也是设计。联动结果：
//  1) 受害者处于扫码配对态时，攻击者用自选 name + 自洽 bundle 可**无认证地
//     制造任意多条 trusted_identities + sessions 行**（无速率上限、无上限清理）；
//  2) 抢先用真实联系人的名字 pin 上攻击者的钥 → 真人随后扫码
//     **永久 IdentityChanged**（Kotlin 仅提示重扫，重扫同样被拒）。
#[test]
fn red1_tofu_pin_poisoning_via_unauthenticated_offer() {
    let mut victim = Device::generate("victim").unwrap();

    // (1) 无认证 DB 灌充：1 个攻击者身份 × N 个自选名字 = N 行信任记录。
    //     攻击者只需受害者处于「扫码配对」态（蓝牙可达 + 正在出示/扫码）。
    let ghosts = 200;
    let mut ok = 0;
    for i in 0..ghosts {
        let ghost = Device::generate(&format!("ghost-{i:04}")).unwrap();
        let bundle = ghost.prekey_bundle().unwrap();
        if victim.process_bundle(ghost.address(), &bundle).is_ok() {
            ok += 1;
        }
    }
    assert_eq!(
        ok, ghosts,
        "RED: 未认证 offer 灌充信任表应全部成功（无速率限制/无容量上限）"
    );

    // (2) 名字抢注：攻击者先以真实联系人的名字 pin 自己 → 真人被永久拒绝。
    let bob = Device::generate("bob").unwrap();
    let mallory = Device::generate("bob").unwrap(); // 同名不同钥
    let bob_bundle = bob.prekey_bundle().unwrap();
    let mallory_bundle = mallory.prekey_bundle().unwrap();

    // 攻击路径：Mallory 的 offer 先到（TOFU 无记录 = 信任）
    victim
        .process_bundle(mallory.address(), &mallory_bundle)
        .expect("RED: 攻击者 bundle 应借 TOFU 首次信任入库");
    // 真人随后扫码：同名异钥 → IdentityChanged（配对该名字永久失败）
    let err = victim
        .process_bundle(bob.address(), &bob_bundle)
        .expect_err("RED: 真实联系人必须被抢注的 pin 挡死");
    assert!(
        matches!(err, dc_core::CoreError::IdentityChanged(ref n) if n == "bob"),
        "RED: 抢注造成的拒绝必须正是真实用户撞上的那类错误: {err:?}"
    );
}

// ══════════════════════ RED 2：iroh ACK 先于应用消费 = 假投递回执 ══════════════════════
//
// 组合：node.rs 的 accept 循环「on_message 回调返回后立刻回 ACK」——回调只是
// 把载荷转交上层；Kotlin 侧 IrohNodeManager 在**异步**协程里按 nodeId 反查
// 联系人，查不到（联系人已删/缓存未命中/名字漂移）或解密失败即静默 return，
// 而 ACK 早已发出。发送侧 DeliveryManager 收 Ok(true) → mark_sent → 消息
// 永久丢失且 UI 记「已送达」。传输层单独看是「尽力而为」没问题；
// 队列层单独看「Ok(true)=已送达」也没问题；联动 = at-least-once 退化成 at-most-once。
#[test]
fn red2_iroh_acks_before_application_delivery() {
    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Node>();
    };

    // 接收方 sink：丢弃一切（等价于联系人反查失败/解密失败/联系人已删）。
    struct DroppingSink;
    impl NodeSink for DroppingSink {
        fn on_message(&self, _: String, _: Vec<u8>) {}
        fn on_ready(&self, _: String, _: String) {}
    }
    // 发送方 sink：收集到达的消息（应为空）。
    struct CollectSink(Arc<Mutex<Vec<(String, Vec<u8>)>>>);
    impl NodeSink for CollectSink {
        fn on_message(&self, from: String, payload: Vec<u8>) {
            self.0.lock().unwrap().push((from, payload));
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
        .enqueue_full(&env([2; 16], [1; 32], b"you-will-lose-me".to_vec()))
        .unwrap();
    let rep = dm.tick(NOW + 1000).unwrap();
    // 攻击成功判据：队列侧记「已送达」，应用侧从未收到。
    assert_eq!(rep.sent, 1, "RED: 传输 ACK 让 DeliveryManager 记为已送达");
    assert!(
        got.lock().unwrap().is_empty(),
        "RED: 接收端应用层却什么都没拿到（sink 丢弃 = 联系人反查失败/解密失败路径）"
    );
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0), "RED: 消息已出队，永不补投");
    sender.stop();
    receiver.stop();
}

// ══════════════════════ RED 3：信箱重放台账随进程死亡（maildrop × 进程生命周期） ══════════════════════
//
// NonceCache 注释承认「跨重启持久化由调用方负责」，但 FFI 面只有
// MailboxManagerHandle::new——**没有任何导出/恢复台账的 API**，Kotlin 想负责
// 也无从下手。Android 前台服务被杀是常态（LMK）：每次进程重启，±5 分钟窗内
// 被嗅探的合法 BucketWrite 全部可原样重放一次（MAC 对、窗口对、台账空）。
// 对比：queue::Db 的 inbox_seen 走 SQLCipher 真持久化——两套收件去重防御强度不一致。
#[test]
fn red3_mailbox_replay_ledger_dies_with_process() {
    let secret = Box::leak(Box::new([7u8; 32]));
    let bucket = generate_bucket_address().unwrap();
    let sender = Identity::from_seed([9; 32]);
    let w = BucketWrite::seal(
        env([3; 16], sender.node_id(), vec![0xAB; 64]),
        secret,
        1,
        NOW,
        [5; 16],
    );

    // 进程 #1：验收通过
    let mut proc1 = MailboxManager::new(4096);
    proc1.submit_write(&w, secret, NOW).expect("首交必须通过");
    // 同进程重放被拒（防御在）
    assert_eq!(
        proc1.submit_write(&w, secret, NOW),
        Err(MailboxError::ReplayRejected),
        "同进程重放必须被拒"
    );
    drop(proc1); // NodeService 被杀 / 进程重启

    // 进程 #2：同一份窗内嗅探写入原样重放 → 通过（台账无从恢复）。
    let mut proc2 = MailboxManager::new(4096);
    assert_eq!(
        proc2.submit_write(&w, secret, NOW),
        Ok(()),
        "RED: 进程重启后重放必须仍被拒，但台账不可持久化使重放复活"
    );
    // 对照组：inbox_seen（queue::Db）重启后仍在——防御强度分裂的证据。
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    assert!(db.record_seen(&[3; 16], NOW).unwrap());
    let db2 = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    assert!(db2.record_seen(&[3; 16], NOW).unwrap(), "RED: 对照——若像 inbox_seen 一样落盘则重启后仍判重");
}

// ══════════════════════ RED 4：读桶 nonce 台账全局 FIFO → 跨桶对驱逐（A6 的读侧翻版） ══════════════════════
//
// 写台账在红队 A6 修复后按「桶对」分区隔离；**读台账没有分区**——
// maildrop::MailboxManager::read_nonces 是一把全局 FIFO（容量 16384）。
// 任一持钥联系人（pair A）刷 16384 次合法读，即可把其他桶对（pair B）
// 未过期的读 nonce 逐出：B 的一条被嗅探读请求随后**原样重放成功**，
// 拉回原读取之后新入库的密文（元数据新鲜度泄露 + 重复取件）。
// 读路径无时间窗（设计使然）、无限速（只有写限速）→ 洪泛零成本。
#[test]
fn red4_read_ledger_global_fifo_cross_pair_eviction() {
    let bucket_b = generate_bucket_address().unwrap();
    let bucket_a = generate_bucket_address().unwrap();
    let secret_b = Box::leak(Box::new(dc_core::mailbox::derive_mailbox_secret(b"red2-b", &bucket_b, 1)));
    let secret_a = Box::leak(Box::new(dc_core::mailbox::derive_mailbox_secret(b"red2-a", &bucket_a, 1)));

    let mut mgr = MailboxManager::new(4096); // read_cap = 16384
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

    // pair A 持钥洪泛：16384 次合法读，无限速 → 全部记账，挤掉 B 的 nonce
    for i in 0..16384u32 {
        let mut n = [0u8; 16];
        n[0] = (i >> 8) as u8;
        n[1] = i as u8;
        n[2] = 0xAA;
        let r = MailboxRead::seal_read(bucket_a, secret_a, 0, n);
        assert!(mgr.read_bucket(&r, secret_a, &st, NOW).is_ok());
    }

    // 攻击成功判据：B 的嗅探读重放复活（ReplayRejected → Ok）
    assert_eq!(
        mgr.read_bucket(&read_b, secret_b, &st, NOW).unwrap().len(),
        1,
        "RED: 全局 FIFO 读台账被另一桶对洪泛驱逐后，读重放必须仍被拒"
    );
}

// ══════════════════════ RED 5：outbox 已发行永不清理 + revive 无状态守卫 ══════════════════════
//
// queue.rs 的 mark_sent 只改 state（行 + 密文体永久留在 outbox 表；全库只有
// prune_seen/prune_dead 两个清理口）。两个联动后果：
//  a) 存储无界增长：每条发出的消息连密文带 CBOR 存档（outbox_env 由 mark_sent
//     删除，但 outbox 行本体保留）永久堆积；
//  b) revive 对**任意** msg_id 生效（不检查 state='dead'）：任何把 sent 行 id
//     传进 revive 的调用路径（死信 UI id 混用、上层 bug、未来批处理）都会把
//     已送达消息复活成 pending → 二次投递。
#[test]
fn red5_sent_rows_retained_forever_and_revive_has_no_state_guard() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let dm = DeliveryManager::new(db, Box::new(|_| Ok(true)));
    for i in 0..64u8 {
        dm.db()
            .lock()
            .unwrap()
            .enqueue_full(&env([i; 16], [1; 32], vec![i; 512]))
            .unwrap();
    }
    dm.tick(NOW).unwrap();
    // 全部「已发出」：pending=0，但 64 行 + 密文仍在表里（无清理路径可触达）
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0));
    // revive 一条已送达消息：无 state 守卫，直接复活
    dm.db().lock().unwrap().revive(&[7; 16]).unwrap();
    let due = dm.db().lock().unwrap().due_envelopes(NOW + 1, 10).unwrap();
    assert_eq!(
        due.len(), 1,
        "RED: revive 必须只对死信生效；已送达消息不应可被复活重投"
    );
    assert_eq!(due[0].msg_id, [7; 16]);
}

// ══════════════════════ RED 6：inbox_seen 台账无容量上限（与 NonceCache 防御强度不一致） ══════════════════════
//
// mailbox::NonceCache 在 A7 修复后有 [64,4096] 双向钳制 + fail-closed；
// 同为「收件去重台账」的 queue::inbox_seen 却**没有容量上限**——外部可见的
// msg_id 是线上攻击者自选字段（信封外层明文），任何能投递信封的路径
// （BLE/iroh/中继转发）灌 N 条异 msg_id 即 N 行持久化记录，7 天保留窗内
// 只增不减（prune_seen 只按时间、不按容量）。磁盘版 NonceCache 洪泛。
#[test]
fn red6_inbox_seen_ledger_is_uncapped() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let flood = 30_000u32;
    for i in 0..flood {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        assert!(db.record_seen(&id, NOW + i as u64).unwrap());
    }
    // 全部驻留：时间窗内 prune 不掉，也没有容量 fail-closed
    assert_eq!(
        db.stats().unwrap().2 as u32, flood,
        "RED: msg_id 为攻击者自选字段，30k 条应触发容量上限；实际无上限全量入库"
    );
    // 对照：同样语义的 NonceCache 有 4096 硬顶（A7 修复）
    let mut nc = dc_core::mailbox::NonceCache::new(30_000);
    let mut accepted = 0u32;
    for i in 0..flood {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        if nc.check_and_insert(&id, NOW, NOW) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 4096, "对照：NonceCache 有硬顶，inbox_seen 没有——防御强度不一致");
}

// ══════════════════════ RED 7：首条握手 token-MAC 无一次性/无上下文绑定 ══════════════════════
//
// first_message_mac(token, bucket, ct) 的密钥只由 QR 载荷里的 token+bucket 派生：
// 不绑定对端名字、时间、会话序号，核心层也**没有任何一次性消费登记**。
// token 的「单次有效」完全依赖「每次出示重新生成载荷」这一 Kotlin 侧习惯。
// 组合攻击：一旦载荷被完整拍摄（3 秒在场门槛内的截屏/录像逐帧、或出示端
// 任何一次载荷复用），(token, bucket) 成为**永久握手能力**——攻击者可对同一
// 出示端在其后的任意一次配对中重放/新建首条握手，MAC 校验恒过。
#[test]
fn red7_first_message_mac_has_no_single_use_or_context_binding() {
    let token = [0x5Au8; 48];
    let bucket = [0x3Cu8; 32];
    let ct = b"prekey-signal-message-bytes";
    let mac = dc_core::handshake::first_message_mac(&token, &bucket, ct);

    // 同一 MAC 可被无限制重复验收（无 nonce/计数器/时间参数可注入）
    for _ in 0..1000 {
        dc_core::handshake::verify_first_message_mac(&token, &bucket, ct, &mac)
            .expect("RED: token-MAC 应有一次性语义，实际可无限重验");
    }
    // 且与对端声称的名字无关（MAC 输入不含 name）——重放帧可对任意配对会话复用
    let mac2 = dc_core::handshake::first_message_mac(&token, &bucket, ct);
    assert_eq!(mac, mac2, "RED: 同输入恒同 MAC，且验证入口无任何上下文参数");
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
        fn on_message(&self, _: String, _: Vec<u8>) {}
        fn on_ready(&self, _: String, _: String) {}
    }
    let n = Node::start("", &[5; 32], Arc::new(Sink)).unwrap();
    let snap = n.export_naddr();
    assert!(n.send("garbage", b"x", 1000).is_err());
    assert!(n.send(&snap, &[], 1000).is_err(), "空载荷必须拒绝");
    assert!(n.send(&snap, &vec![0u8; 256 * 1024 + 1], 1000).is_err(), "超限载荷必须拒绝");
    n.stop();
}
