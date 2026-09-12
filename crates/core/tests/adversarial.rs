//! adversarial.rs —— 独立第二轮红队套件（不重复作者 redteam.rs / security_bruteforce.rs 已覆盖面）。
//!
//! 攻击类别（作者三轮均未覆盖）：
//!   A. UniFFI 边界：u64→i64 裸铸、构造参数无上界、门禁/存储解耦
//!   B. 跨模块组合：FFI 参数 × 内部钟高水位、偏移重置 × 回滚钳制、配对单槽 × 双源认证缺失
//!   C. 状态机序列：同 msg_id 二次入队偷换、共享 nonce 台账跨桶污染、sender 字段伪造绕限速
//!   D. 资源上限：hard_cap 只有下限没有上限、软上限非硬上限
//!   E. 算术边界：u64 溢出点（官方流程之外但公开 API 可达）
//!
//! 断言约定（与 redteam.rs 相同）：每个测试断言「安全属性必须成立」。
//! 测试失败 = 攻击成功 = RED（真实漏洞，断言消息以 RED: 开头直接点名）；
//! 通过 = 系统扛住 = GREEN。全部确定性：from_seed 身份、无 sleep、无真实时钟。

use dc_core::adaptive::{Metrics, PolicyEngine, Tier};
use dc_core::clock::{InternalClock, Source};
use dc_core::delivery::DeliveryManager;
use dc_core::envelope::{Envelope, PayloadKind};
use dc_core::ffi::{BucketStorageHandle, MailboxManagerHandle};
use dc_core::identity::Identity;
use dc_core::mailbox::{derive_mailbox_secret, BucketWrite, NonceCache};
use dc_core::maildrop::{MailboxError, MailboxManager, WRITES_PER_MINUTE};
use dc_core::nodekey::{NodeKeyAnnouncement, NodeKeyRing, DEFAULT_OVERLAP_MS};
use dc_core::queue::Db;
use dc_core::relay::{RelayGuard, RelayTicket};
use dc_core::retry::RetryPolicy;
use dc_core::settings::Settings;

const NOW: u64 = 1_700_000_000_000;

fn quiet_panic<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    r
}

fn hex32(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mk_env(sender: [u8; 32], msg_id: [u8; 16], body: Vec<u8>, ts: u64) -> Envelope {
    Envelope {
        msg_id,
        sender,
        recipient: Some([9; 32]),
        group: None,
        kind: PayloadKind::Text,
        body,
        sent_at_ms: ts,
        ttl_hops: 6,
    }
}

fn seal(sender: [u8; 32], msg_id: [u8; 16], secret: &[u8; 32], ts: u64, nonce: [u8; 16]) -> BucketWrite {
    BucketWrite::seal(mk_env(sender, msg_id, vec![7; 64], ts), secret, 1, ts, nonce)
}

// ════════════════════ RED A1：FFI local_ms 裸铸 i64 → 单次调用永久钉死内部钟 ════════════════════

/// ffi.rs `submit(local_ms: u64)` 直接 `local_ms as i64` 喂给 InternalClock（无任何钳制；
/// 对照组：queue::Db 对同类输入有 clamp_ms，FFI 路径没有）。local_ms = i64::MAX 一次调用即把
/// internal_high_water_ms 抬到 i64::MAX——高水位只增不减，此后**所有**真实时间戳的合法写入
/// 永远判「过旧」全拒（门禁级 DoS），而按毒化钟封时间戳的内部人写入反而放行：
/// 防回拨高水位从「安全机制」变成「攻击者可一次钉死的开关」。
/// 作者修了持久层恢复路径（restore_high_water 钳制，见其 red4）与 Db 路径（clamp_ms），
/// 漏了这条活的 FFI 输入路径。
#[test]
fn red_a1_ffi_local_ms_cast_pins_clock_at_i64max_forever() {
    let h = MailboxManagerHandle::new(1024);
    let secret = derive_mailbox_secret(b"adv-a1", &[0xA1; 32], 1);
    let shex = hex32(&secret);

    // 基线：毒化前，真实时刻的合法写入通过
    let w0 = seal([1; 32], [1; 16], &secret, NOW, [1; 16]);
    let r0 = h.submit(serde_json::to_string(&w0).unwrap(), shex.clone(), NOW);
    assert!(matches!(&r0, Ok(s) if s == "accepted"), "基线失败：毒化前合法写入必须通过");

    // 攻击：一次调用，local_ms = i64::MAX（u64 值 9_223_372_036_854_775_807 `as i64` 不回绕，
    // 恰好是「本地钟读数被垃圾源/被篡改组件抬高」的最坏合法 u64 输入）
    let poison_local = i64::MAX as u64;
    let _ = h.submit(serde_json::to_string(&w0).unwrap(), shex.clone(), poison_local);

    // 毒化后：新的合法写入（真实时刻）必须仍然通过 —— 实际被永久全拒
    let w1 = seal([1; 32], [2; 16], &secret, NOW + 1_000, [2; 16]);
    let r1 = h.submit(serde_json::to_string(&w1).unwrap(), shex.clone(), NOW + 1_000);
    assert!(
        matches!(&r1, Ok(s) if s == "accepted"),
        "RED: 单次 FFI 调用（local_ms=i64::MAX 裸铸）把高水位钉死在 i64::MAX，\
         此后所有真实时间戳的合法写入永久 WindowExceeded —— 实际: {:?}",
        r1.as_ref().err().map(|e| e.to_string())
    );

    // 持续性：再往后任何真实时刻依旧全拒（不可恢复，直到公元 29 万年）
    let w2 = seal([1; 32], [3; 16], &secret, NOW + 2_000, [3; 16]);
    let r2 = h.submit(serde_json::to_string(&w2).unwrap(), shex.clone(), NOW + 2_000);
    assert!(
        matches!(&r2, Ok(s) if s == "accepted"),
        "RED: 毒化不可恢复（第二次提交仍被拒）——实际: {:?}",
        r2.as_ref().err().map(|e| e.to_string())
    );

    // 攻击收益：按毒化钟封 ts 的内部人写入（攻击者形态）反而畅通
    let evil_ts = (i64::MAX - 1_000) as u64;
    let we = seal([1; 32], [4; 16], &secret, evil_ts, [4; 16]);
    let re = h.submit(serde_json::to_string(&we).unwrap(), shex.clone(), poison_local);
    assert!(
        matches!(&re, Ok(s) if s == "accepted"),
        "RED: 毒化钟下「攻击者形态时间戳」放行 —— 门禁语义整体反转。实际: {:?}",
        re.as_ref().err().map(|e| e.to_string())
    );
}

// ════════════════════ RED A2：偏移重置 × 回滚钳制交互 —— 防回拨高水位被「洗」回过去 ════════════════════

/// clock.rs `now()`：偏移变化时 `internal_high_water_ms = internal`（整体重置基线，
/// 本意是毒偏移撤离后不残留旧峰）。但重置**不检测 rollback_detected**：
/// 系统钟被拨回 1 年 + 任一偏移变化（合法 NTP 微调也算）→ 高水位从 T0 直接缩到
/// 「拨回后的本地钟 + 新偏移」→ 内部钟返回比历史上任何观测值都早的时间。
/// 防回拨钳制（本模块核心安全属性）被一次普通的偏移变化整个击穿。
#[test]
fn red_a2_offset_change_deflates_rollback_high_water_pin() {
    let t0 = 1_700_000_000_000i64;
    let mut c = InternalClock::new();

    // 1) 正常运行建立高水位 T0
    assert_eq!(c.now(t0), t0, "基线：内部钟 = 本地钟");

    // 2) 双源一致校准 -2min（≤ NETWORK_ADOPTION_CAP_MS，合法范围内）
    c.on_network_sync(1, t0 + 60_000, t0 + 60_000 - 120_000);
    c.on_network_sync(2, t0 + 60_000, t0 + 60_000 - 120_000);
    assert_eq!(c.source(t0 + 61_000), Source::Network, "基线：双源校准被采纳");

    // 3) 系统钟被拨回 1 年（rollback 攻击本体）——此时偏移恰好变化（-0 → -2min）
    let rolled = t0 - 365 * 86_400_000;
    let out = c.now(rolled);

    // 安全属性：内部钟不得低于已建立的高水位 T0
    assert!(out >= t0,
        "RED: 回滚期间一次偏移变化把高水位整体重置到回滚后时间，内部钟返回 {out} < 高水位 {t0}，\
         防回拨钳制被击穿");
    assert!(c.high_water_ms() >= t0 as u64,
        "RED: 高水位记录本身被洗掉（{} < {t0}），后续时间链全部以回滚时间为基线",
        c.high_water_ms());

    // 4) 洗掉之后回不来了：偏移稳定后高水位继续从「过去」起算
    let out2 = c.now(rolled + 1_000);
    assert!(out2 >= t0,
        "RED: 高水位一旦被洗掉即不可恢复（第二次仍返回 {out2} < {t0}）");
}

// ════════════════════ RED A3：双源配对单槽 + source_id 无认证 → 恶意源永久捣毁诚实配对 ════════════════════

/// clock.rs 的双源交叉验证假设「来源 = 诚实 NTP 服务器」，但 `source_id` 是调用方
/// 随便填的 u8，`pending_network` 是**单槽**。中间人同时控两条流时：
/// 诚实源 1 挂起 → 毒源 3 插入（与槽内不一致 → 双双作废）→ 诚实源 2 挂起 →
/// 毒源 4 与毒源 3 的历史……毒源自配对成功采纳；诚实对**永远凑不进同一个槽**。
/// 采纳后诚实纠偏（-Δ）还受 ±2min 采纳上限约束，钟被攻击者以最高速率（2min/10min）
/// 单向牵引且诚实侧无法拉回。
#[test]
fn red_a3_network_pending_slot_desync_hijacks_dual_source() {
    let t = 1_700_000_000_000i64;

    // 基线：无人干扰时，两个诚实源正常配对采纳
    let mut honest = InternalClock::new();
    honest.on_network_sync(1, t, t);
    honest.on_network_sync(2, t + 1_000, t + 1_000);
    assert_eq!(honest.now(t + 2_000), t + 2_000, "基线：诚实双源应采纳 +0");

    // 攻击：毒源 3/4 交错插入，诚实源 1/2 永远无法在槽内相遇
    let mut c = InternalClock::new();
    c.on_network_sync(1, t, t);                                  // 诚实源1 挂起
    c.on_network_sync(3, t, t + 120_000);                        // 毒源3：不一致 → 双双作废
    c.on_network_sync(2, t + 1_000, t + 1_000);                  // 诚实源2 挂起（对1已被作废）
    c.on_network_sync(4, t + 1_000, t + 1_000 + 120_000);        // 毒源4 与毒源3 自配对 → 采纳 +2min
    assert_eq!(c.now(t + 2_000), t + 2_000,
        "RED: 毒源自配对抢下唯一槽位，钟被拨快 2min；诚实双源从未被采纳");

    // 第二轮（10min 冷却后）：诚实对与毒对在槽内依旧无法相遇——
    // 每个新样本要么与槽内样本失配作废、要么占槽等待，毒对（3/4）同样
    // 凑不齐一致对。FIXED（红队 A3：挂起槽 5 分钟超时 + 采纳上限/冷却）：
    // 钟纹丝不动，毒对「+2min/轮」的棘轮被整体拒绝。
    c.on_network_sync(1, t + 601_000, t + 601_000);
    c.on_network_sync(3, t + 601_000, t + 601_000 + 240_000);    // 捣毁诚实源1
    c.on_network_sync(2, t + 601_001, t + 601_001);              // 诚实源2 挂起
    c.on_network_sync(4, t + 601_001, t + 601_001 + 240_000);    // 与诚实源2 失配作废
    assert_eq!(c.now(t + 602_000), t + 602_000,
        "FIXED: 毒对无法自配对采纳（+4min 棘轮被拒），内部钟保持诚实读数");
}

// ════════════════════ RED A4：同 msg_id 二次 enqueue_full → 已入队消息在投递前被偷换 ════════════════════

/// queue.rs enqueue_full 的注释假设「同 msg_id 重复入队：同一消息内容一致，无害」。
/// 但 msg_id 是**线上攻击者自选的 16 字节**：outbox 行 INSERT OR IGNORE（保留首条的
/// recipient/created_ms），outbox_env 存档 INSERT OR REPLACE（被第二份内容覆盖）。
/// due_envelopes 优先按存档重建 → 投递内容 = 攻击者第二次塞入的信封（连 recipient 一起换），
/// 与 outbox 行里的元数据彻底分叉。任何把外来信封转投出站的路径（人群转发逐跳重投）
/// 都能让攻击者在消息发出前任意改写其内容与收件人。
#[test]
fn red_a4_enqueue_full_same_msg_id_swaps_undelivered_content() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let bob = [0xB0; 32];
    let mallory = [0xE5; 32];
    let x = [0x42; 16];

    let first = Envelope {
        msg_id: x, sender: [1; 32], recipient: Some(bob), group: None,
        kind: PayloadKind::Text, body: vec![1], sent_at_ms: 1000, ttl_hops: 6,
    };
    let second = Envelope {
        msg_id: x, sender: [2; 32], recipient: Some(mallory), group: None,
        kind: PayloadKind::Text, body: vec![2, 2, 2], sent_at_ms: 2000, ttl_hops: 6,
    };
    db.enqueue_full(&first).unwrap();
    db.enqueue_full(&second).unwrap(); // 同 msg_id、完全不同的内容/收件人

    let rows = db.pending(10).unwrap();
    assert_eq!(rows.len(), 1, "outbox 行幂等忽略（符合注释假设）");

    // 安全属性：已入队消息的内容在投递前不得被同 id 重放偷换
    let due = db.due_envelopes(5000, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].body, vec![1],
        "RED: outbox_env 被第二次入队 REPLACE，投递内容被偷换为攻击者第二份 body（实际 {:?}）",
        due[0].body);
    assert_eq!(due[0].recipient, Some(bob),
        "RED: 收件人被同 msg_id 偷换为 Mallory（实际 {:?}），而 outbox 行 recipient 仍是 Bob —— 行/存档分叉",
        due[0].recipient);
}

// ════════════════════ RED A5：sender 字段可由持钥者任意伪造 → 30/min 限速形同虚设 ════════════════════

/// maildrop.rs 限速键 = envelope.sender。MAC 确实绑定 sender——但计算 MAC 的正是
/// **发送方本人**：持有该对 mailbox secret 的联系人可以给每条写入签一个不同的
/// sender NodeId，每个新 sender 都拿到一只满桶（30 token）。30/min/对的配额
/// 对唯一真实的威胁主体（密钥持有者）约束力为零。
#[test]
fn red_a5_sender_field_spoofing_defeats_per_pair_rate_limit() {
    let secret = derive_mailbox_secret(b"adv-a5", &[0xA5; 32], 1);

    // 基线：同一 sender 第 31 封被限速（限速机制本身在运作）
    let mut ctrl = MailboxManager::new(4096);
    for i in 0..WRITES_PER_MINUTE {
        ctrl.submit_write(&seal([7; 32], [i as u8; 16], &secret, NOW, [i as u8; 16]), &secret, NOW)
            .expect("基线：前 30 封应放行");
    }
    assert_eq!(
        ctrl.submit_write(&seal([7; 32], [99; 16], &secret, NOW, [99; 16]), &secret, NOW),
        Err(MailboxError::RateLimited),
        "基线：同 sender 第 31 封必须限速"
    );

    // 攻击：同一把密钥，每封换一个 sender —— 100 封在同一分钟内全部放行
    let mut mgr = MailboxManager::new(4096);
    let mut accepted = 0u32;
    for i in 0..100u32 {
        let mut sender = [0u8; 32];
        sender[0] = (i >> 8) as u8;
        sender[1] = i as u8;
        sender[2] = 0x5A;
        let mut msg_id = [0u8; 16];
        msg_id[0] = (i >> 8) as u8;
        msg_id[1] = i as u8;
        msg_id[2] = 0x5A;
        let w = seal(sender, msg_id, &secret, NOW, msg_id);
        if mgr.submit_write(&w, &secret, NOW).is_ok() {
            accepted += 1;
        }
    }
    assert!(accepted <= WRITES_PER_MINUTE,
        "RED: 持钥者伪造 {accepted} 个 sender 身份，同一分钟内写入 {accepted} 封 >> 30 封/分钟/对 \
         ——按对限速被 sender 字段伪造整体绕过");
}

// ════════════════════ RED A6：共享 msg_id 台账跨桶 fail-closed → 单个联系人冻结整个信箱 ════════════════════

/// maildrop.rs 声称「跨桶复用同一实例也安全……互不串扰」（FFI MailboxManagerHandle 正是
/// 单实例服务所有桶：secret 按调用传入）。但 msg_id 台账是**全局共享**且 fail-closed：
/// 一个恶意联系人（持有自己那把合法 secret）用 4096 个伪造 sender/msg_id 灌满台账后，
/// **其他所有桶**的诚实联系人写入全部被误判为「重放」拒绝，直到 ~9 分钟后过期排空；
/// 攻击者每 9 分钟补一轮 4096 条即可永久冻结整个信箱服务。
/// （与 A5 叠加：限速对这种攻击无效，因为每个伪造 sender 都有独立满桶。）
///
/// FIXED（红队 A5 + A6）：限速键与 msg_id 台账都绑定**桶对**（mailbox secret 的
/// 指纹）——单对洪泛被限速层压到 ≤30 封/分钟（A5），台账按对分区（A6）：
/// 洪泛尝试的 msg_id 只记入恶意对自己那本台账（去重先于限速的「拒绝重探」
/// 语义不变），触顶后 fail-closed 也只限本对；其他桶的诚实写入不再被牵连。
#[test]
fn red_a6_shared_nonce_ledger_fails_closed_across_buckets() {
    let s_evil = derive_mailbox_secret(b"adv-a6-evil", &[0xE1; 32], 1);
    let s_honest = derive_mailbox_secret(b"adv-a6-honest", &[0x03; 32], 1);
    let mut mgr = MailboxManager::new(4096); // 单实例服务两个桶（FFI 的真实形态）

    // 恶意联系人：4096 条「合法 MAC」写入（每个都是新 sender/msg_id）
    let mut accepted = 0u32;
    for i in 0..4096u32 {
        let mut sender = [0u8; 32];
        sender[0] = (i >> 8) as u8;
        sender[1] = i as u8;
        sender[2] = 0xEE;
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        id[2] = 0xEE;
        let w = seal(sender, id, &s_evil, NOW, id);
        if mgr.submit_write(&w, &s_evil, NOW).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, WRITES_PER_MINUTE,
        "FIXED: 单对洪泛被限速层压到 30 封/分钟（限速键=桶对，伪造 sender 拆不了配额）");
    // 去重先于限速（拒绝重探语义）：洪泛尝试的 4096 个 msg_id 全部记入
    // 恶意对**自己那本**台账并恰好触顶——其他桶的台账分毫未动
    assert_eq!(mgr.nonce_cache_len(), 4096, "恶意对台账被自己的洪灌满（按对隔离）");

    // 攻击效果评估：**另一个桶**的诚实联系人（自己的合法 secret、全新 msg_id）
    // 不受恶意对任何影响——台账按对分区、限速按对计费
    let honest_w = seal([0x33; 32], [0x33; 16], &s_honest, NOW, [0x33; 16]);
    let honest_out = mgr.submit_write(&honest_w, &s_honest, NOW);
    assert_eq!(honest_out, Ok(()),
        "FIXED: 单个联系人的洪泛不再把其他桶的诚实写入 fail-closed 误判为重放 \
         ——实际 {:?}",
        honest_out.as_ref().err());

    // 恶意对的下一封：本对台账满员 → fail-closed（洪泛的代价，只限本对）
    let mut over = [0u8; 16];
    over[0] = 0xFF;
    assert_eq!(
        mgr.submit_write(&seal([0xEE; 32], over, &s_evil, NOW, over), &s_evil, NOW),
        Err(MailboxError::ReplayRejected),
        "恶意对台账满员后 fail-closed（对攻击者同样生效）"
    );

    // 下一分钟：诚实对继续可写；恶意对的满员台账在过期排空前持续 fail-closed
    let later = NOW + 61_000;
    let honest_w2 = seal([0x33; 32], [0x34; 16], &s_honest, later, [0x34; 16]);
    assert_eq!(mgr.submit_write(&honest_w2, &s_honest, later), Ok(()),
        "恢复路径：诚实对下一分钟继续可写（限速/台账均按对隔离）");
    let evil_w2 = seal([0xEE; 32], [0x35; 16], &s_evil, later, [0x35; 16]);
    assert_eq!(mgr.submit_write(&evil_w2, &s_evil, later), Err(MailboxError::ReplayRejected),
        "恶意对满员台账过期排空前持续 fail-closed（洪泛不可自愈式重试）");
}

// ════════════════════ RED A7：hard_cap 只有下限钳制没有上界 → 文档承诺的内存上界失效 ════════════════════

/// mailbox.rs NonceCache 文档：「攻击_backstop = max(cap, 4096)（约 200KB 内存上界）」。
/// 实现只有 max(cap, 4096)——**下限**钳制；FFI 构造器 `MailboxManagerHandle::new(cap: u32)`
/// 把任意 u32 直通 hard_cap。cap = u32::MAX 时「硬上限」变成 42.9 亿条（≈数百 GB），
/// 洪泛 fail-closed 背板整个失效， insider 洪泛可无界吃内存直到 OOM。
#[test]
fn red_a7_nonce_cache_hard_cap_has_no_upper_bound() {
    // 基线：合理容量下 fail-closed 背板正常工作
    let mut ok = NonceCache::new(4096);
    for i in 0..5000u32 {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        ok.check_and_insert(&id, NOW, NOW);
    }
    assert_eq!(ok.len(), 4096, "基线：合理容量下满员即拒（背板有效）");

    // 攻击：FFI 构造参数 cap = u32::MAX 直通 hard_cap，背板消失
    let mut bomb = NonceCache::new(u32::MAX as usize);
    let mut accepted = 0u32;
    for i in 0..10_000u32 {
        let mut id = [0u8; 16];
        id[0] = (i >> 8) as u8;
        id[1] = i as u8;
        id[2] = 0xB0;
        if bomb.check_and_insert(&id, NOW, NOW) {
            accepted += 1;
        }
    }
    assert!(accepted < 10_000,
        "RED: 构造参数 u32::MAX 直通 hard_cap，{accepted} 条全部驻留——文档承诺的 \
         「约 200KB 内存上界」不存在任何上界钳制，构造参数即内存炸弹开关");
}

// ════════════════════ RED A8：NonceCache 过期算术 u64 溢出 panic（公开 API 可达） ════════════════════

/// `check_and_insert` 的 retain 闭包 `*exp + 2*60_000 > now_ms` 是裸加法。ts_ms = u64::MAX
/// （毒化时钟链的下游产物——作者在 red4/red7/red8 中已把这类输入定为攻击面）时
/// expiry 饱和到 u64::MAX，**第二次**调用（任意 msg_id）在 retain 里 u64::MAX + 120_000
/// 溢出 → debug 构建直接 panic。官方 verify_inbound 流程有窗口前置校验够不到这里，
/// 但 NonceCache 是 pub 类型 + pub 方法（文档要求调用方自行持有并持久化台账），
/// 合同上就接受任意 u64 ts_ms。
#[test]
fn red_a8_nonce_cache_expiry_add_overflow_panic() {
    let mut c = NonceCache::new(100);
    let id1 = [0x11; 16];
    let id2 = [0x22; 16];
    assert!(c.check_and_insert(&id1, u64::MAX, 0), "首插应成功");
    let r = quiet_panic(|| c.check_and_insert(&id2, u64::MAX, 0));
    assert!(r.is_ok(),
        "RED: 第二次 check_and_insert 在 retain 的 `exp + 120_000` 上 u64 溢出 panic（debug）\
         ——公开 API 对合同内输入（u64::MAX 台账条目）不健壮");
}

// ════════════════════ RED A9：store_write 不经门禁直写桶 → 未认证内容以「已验收」身份入库并被读出 ════════════════════

/// ffi.rs 把「门禁（submit）」与「存储（store_write）」拆成两个无绑定的 API：
/// store_write 对 write_json **不做任何 MAC 校验**（注释只靠「Kotlin 应先 submit」的约定），
/// read_bucket 取回时也不复验桶内条目。任何拿到存储句柄的代码路径（备份恢复、
/// 同步、未来的中继实现）都能把 MAC 无效的写灌进桶，被持钥者的合法读请求原样取走。
#[test]
fn red_a9_store_write_ingests_unverified_writes_served_by_read_path() {
    let st = BucketStorageHandle::new();
    let bucket = [0xA9; 32];
    let secret = derive_mailbox_secret(b"adv-a9", &bucket, 1);

    let w = seal([1; 32], [9; 16], &secret, NOW, [9; 16]);
    let mut bad = w.clone();
    bad.mac[0] ^= 1; // MAC 已坏：任何门禁都会拒

    // 安全属性：MAC 无效的写不得入库
    let stored = st.store_write(hex32(&bucket), serde_json::to_string(&bad).unwrap());
    assert!(stored.is_err(),
        "RED: MAC 无效的写未经任何校验直接入库（store_write 与门禁零绑定）——实际 Ok({:?})",
        stored.ok());

    // 且被读路径当作桶内容原样端给持钥者
    let read_json = dc_core::ffi::seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 0).unwrap();
    let out = st.read_bucket(read_json, hex32(&secret), 0, NOW);
    match out {
        Ok(json) => {
            let list: Vec<BucketWrite> = serde_json::from_str(&json).unwrap();
            assert!(list.is_empty(),
                "RED: 未认证写被读路径当作桶内容返回（{} 条）——读侧无完整性复验", list.len());
        }
        Err(e) => panic!("RED: 读路径异常（存储了坏行后读桶出错）: {e}"),
    }
}

// ════════════════════ RED A10：FFI local_ms = 2^63 → i64::MIN → peak_cluster 减法溢出 panic ════════════════════

/// 同一 `local_ms as i64` 裸铸的另一面：u64 值恰为 2^63 时铸成 i64::MIN。
/// `peak_cluster` 的 `local_ms - 30*60*1000` 是裸减法（i64::MIN - 1_800_000 溢出）
/// → debug 构建 panic；panic 发生在 clock Mutex 持锁路径上 → 锁中毒 →
/// **该 FFI 句柄此后所有调用永久 panic**（UniFFI 侧表现为整条信箱门禁不可用）。
/// 一次调用、一个参数、进程级不可恢复。
#[test]
fn red_a10_ffi_local_ms_i64min_overflows_peak_cluster_and_poisons_handle() {
    let h = MailboxManagerHandle::new(1024);
    let secret = derive_mailbox_secret(b"adv-a10", &[0xAA; 32], 1);
    let shex = hex32(&secret);
    let w = seal([1; 32], [1; 16], &secret, NOW, [1; 16]);
    let json = serde_json::to_string(&w).unwrap();

    // 直接内核层复现：now(i64::MIN) 必须不 panic
    let mut c = InternalClock::new();
    let direct = quiet_panic(|| c.now(i64::MIN));
    assert!(direct.is_ok(), "RED: InternalClock::now(i64::MIN) 在 peak_cluster `local_ms - 30min` 溢出 panic");

    // FFI 层复现：local_ms = 2^63 → submit panic
    let r1 = quiet_panic(|| h.submit(json.clone(), shex.clone(), 0x8000_0000_0000_0000));
    assert!(r1.is_ok(), "RED: FFI submit(local_ms=2^63) 触发减法溢出 panic（UniFFI 边界无钳制直达内核算术）");

    // 放大：panic 使 clock Mutex 中毒 → 句柄永久不可用（普通合法调用也炸）
    let r2 = quiet_panic(|| h.submit(json, shex, NOW));
    assert!(r2.is_ok(),
        "RED: 一次毒参数调用令 clock Mutex 中毒，句柄所有后续调用（含合法输入）永久 panic —— 句柄级永久 DoS");
}

// ════════════════════════════════════ GREEN：系统扛住的攻击面 ════════════════════════════════════

/// 并发 + 时序交错：4 线程经同一 FFI 句柄并发 submit，交错点任意——
/// 不变量与顺序无关：1000 个不同 msg_id 恰好各被接受一次，二轮全部判重。
/// （红队 A5 修复后限速键=桶对：各写入用独立密钥对，并发压力与限速解耦。）
#[test]
fn green_g1_concurrent_submit_no_double_accept() {
    let h = std::sync::Arc::new(MailboxManagerHandle::new(4096));

    let mut jobs = Vec::new();
    for t in 0..4u32 {
        let h = h.clone();
        jobs.push(std::thread::spawn(move || {
            let mut ok = 0u32;
            for i in 0..250u32 {
                let g = t * 250 + i;
                let mut pair = [0u8; 32];
                pair[0] = (g >> 8) as u8;
                pair[1] = g as u8;
                pair[2] = 0x11;
                let secret = derive_mailbox_secret(b"adv-g1", &pair, 1);
                let shex = hex32(&secret);
                let mut sender = [0u8; 32];
                sender[0] = (g >> 8) as u8;
                sender[1] = g as u8;
                sender[2] = 0x11;
                let mut id = [0u8; 16];
                id[0] = (g >> 8) as u8;
                id[1] = g as u8;
                id[2] = 0x11;
                let w = seal(sender, id, &secret, NOW, id);
                if h.submit(serde_json::to_string(&w).unwrap(), shex, NOW).is_ok() {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let total: u32 = jobs.into_iter().map(|j| j.join().unwrap()).sum();
    assert_eq!(total, 1000, "并发提交：每条恰被接受一次（无丢失/无重复消费）");

    // 二轮重放：全部拒绝（台账在并发交错下依然完整）
    let mut replay_ok = 0u32;
    for g in 0..1000u32 {
        let mut pair = [0u8; 32];
        pair[0] = (g >> 8) as u8;
        pair[1] = g as u8;
        pair[2] = 0x11;
        let secret = derive_mailbox_secret(b"adv-g1", &pair, 1);
        let shex = hex32(&secret);
        let mut sender = [0u8; 32];
        sender[0] = (g >> 8) as u8;
        sender[1] = g as u8;
        sender[2] = 0x11;
        let mut id = [0u8; 16];
        id[0] = (g >> 8) as u8;
        id[1] = g as u8;
        id[2] = 0x11;
        let w = seal(sender, id, &secret, NOW, id);
        if h.submit(serde_json::to_string(&w).unwrap(), shex, NOW).is_ok() {
            replay_ok += 1;
        }
    }
    assert_eq!(replay_ok, 0, "并发后重放必须 100% 拒绝");
}

/// SendFn panic 风暴：回调每条都 panic（Kotlin 异常经 FFI 的最坏形态）——
/// catch_unwind 兜底、计数完整、Mutex 不中毒、重绑通道后投递恢复、零丢失。
#[test]
fn green_g2_sendfn_panic_storm_accounted_and_recoverable() {
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let policy = RetryPolicy { max_attempts: 2, base_delay_ms: 1, max_delay_ms: 2 };
    let dm = DeliveryManager::with_policy(
        db,
        Some(Box::new(|_: &Envelope| panic!("kotlin callback boom"))),
        policy,
        16,
    );
    for i in 0..5u8 {
        let mut e = mk_env([1; 32], [i; 16], vec![1, 2, 3], 1000);
        e.recipient = Some([8; 32]);
        dm.db().lock().unwrap().enqueue_full(&e).unwrap();
    }
    // 第一拍：5 条全部 panic → 全部计为 errored，无丢失
    let r1 = quiet_panic(|| dm.tick(2000).unwrap()).unwrap();
    assert_eq!((r1.attempted, r1.errored, r1.sent, r1.dead), (5, 5, 0, 0), "panic 必须逐条计入 errored");
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (5, 0, 0), "panic 不丢消息");
    // 第二拍（退避过后）：attempts 耗尽 → 全部转死信
    let r2 = quiet_panic(|| dm.tick(10_000).unwrap()).unwrap();
    assert_eq!((r2.attempted, r2.dead), (5, 5), "第二次 panic 后转死信");
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 5, 0));
    // Mutex 未中毒：重绑通道 + 复活 → 正常投递
    dm.set_send_fn(Box::new(|_: &Envelope| Ok(true)));
    for i in 0..5u8 {
        dm.db().lock().unwrap().revive(&[i; 16]).unwrap();
    }
    let r3 = dm.tick(20_000).unwrap();
    assert_eq!(r3.sent, 5, "panic 风暴后句柄仍完全可用");
    assert_eq!(dm.db().lock().unwrap().stats().unwrap(), (0, 0, 0));
}

/// 转发票极端字段（合法签名——任何人都能生成密钥对，等同攻击者自签）：
/// TTL/未来/过期/倒挂/expiry=u64::MAX 全部被拒；且 expiry+skew 溢出点
/// 因「未来签发校验先行」不可达（无 panic）。
#[test]
fn green_g3_relay_ticket_extreme_signed_fields_all_rejected() {
    let origin = Identity::from_seed([0x21; 32]);
    let dest = Identity::from_seed([0x22; 32]);
    let mk = |issued: u64, expiry: u64| {
        let mut t = RelayTicket::new(&dest.node_id(), &origin.node_id(), issued, expiry, [9; 16], [1; 32]);
        t.sign(&origin).unwrap();
        t
    };
    let cases: [(u64, u64, &str); 6] = [
        (u64::MAX, u64::MAX, "issued=expiry=u64::MAX"),
        (0, u64::MAX, "远古签发 + expiry=u64::MAX"),
        (NOW, u64::MAX, "expiry=u64::MAX（溢出点试探）"),
        (NOW + 600_000, NOW + 600_000 + 3_600_000, "未来 10min 签发（>2min 偏移容差）"),
        (NOW, NOW - 200_000, "已过期 3.3min（>2min 容差）"),
        (u64::MAX - 7_200_000, u64::MAX, "TTL 恰 2h 但 issued 在未来"),
    ];
    for (issued, expiry, tag) in cases {
        let t = mk(issued, expiry);
        assert!(t.verify(NOW, [1; 32]).is_err(), "RED: 极端票被接受（{tag}）");
        let mut g = RelayGuard::new(64);
        assert!(!g.accept(&t, NOW, [1; 32]), "RED: 极端票入环（{tag}）");
    }
    // 对照：正常票必须通过（门没有焊死）
    let ok = mk(NOW, NOW + 3_600_000);
    assert!(ok.verify(NOW, [1; 32]).is_ok(), "对照：正常票必须通过");
    let mut g = RelayGuard::new(64);
    assert!(g.accept(&ok, NOW, [1; 32]), "对照：正常票必须入环");
}

/// 持久层毒化注入：伪造签名 / serial=0 / 63 字节签名 / 过期窗倒挂——
/// NodeKeyRing.upsert 与 restore 逐条验签，毒条目全部拒绝，环不被改变。
#[test]
fn green_g4_nodekey_ring_poisoned_restore_entries_rejected() {
    let peer = Identity::from_seed([0x31; 32]);
    let node1 = Identity::from_seed([0x32; 32]).node_id();
    let mut good = NodeKeyAnnouncement::new(&peer.node_id(), &node1, 1, NOW, DEFAULT_OVERLAP_MS);
    good.sign(&peer).unwrap();

    let mut forged = good.clone();
    forged.serial = 2;
    forged.node_key = [7; 32];
    forged.sig = vec![0u8; 64];
    let mut zero = good.clone();
    zero.serial = 0;
    let mut badlen = good.clone();
    badlen.sig = vec![1u8; 63];
    let mut inverted = good.clone();
    inverted.serial = 3;
    inverted.not_before_ms = NOW + 1000;
    inverted.not_after_ms = NOW; // not_after <= not_before
    inverted.sig = peer.sign(&inverted.signing_payload_pub()).to_bytes().to_vec();

    let mut ring = NodeKeyRing::new();
    ring.upsert(&good, NOW).unwrap();
    for e in [&forged, &zero, &badlen, &inverted] {
        assert!(ring.upsert(e, NOW).is_err(), "RED: 毒化持久条目被接受（serial={}）", e.serial);
    }
    assert_eq!(ring.current(&peer.node_id(), NOW), Some(&node1), "环未被毒化输入改变");

    let mut ring2 = NodeKeyRing::new();
    assert!(ring2.restore(vec![forged.clone(), good.clone()], NOW).is_err(),
        "restore 遇毒条目必须整体失败");
    assert_eq!(ring2.current(&peer.node_id(), NOW), None, "毒条目不得混入新环");
}

/// 重试/队列算术极端：base/max = u64::MAX、0/0、attempts=0 —— 无 panic、
/// delay 有界、now+delay 饱和进入 i64 列（作者只测过 now_ms=u64::MAX 这一侧）。
#[test]
fn green_g5_retry_queue_extreme_delays_no_panic() {
    let pmax = RetryPolicy { max_attempts: u32::MAX, base_delay_ms: u64::MAX, max_delay_ms: u64::MAX };
    assert_eq!(pmax.next_delay_ms(1).unwrap(), u64::MAX, "span=1 时 jitter=0，delay=base");
    let pzero = RetryPolicy { max_attempts: 10, base_delay_ms: 0, max_delay_ms: 0 };
    assert_eq!(pzero.next_delay_ms(1).unwrap(), 0, "零延迟策略不 panic");
    assert!(pmax.next_delay_ms(0).is_err());
    assert!(pzero.next_delay_ms(10).is_err());

    // 队列整合：delay=u64::MAX → now+delay 饱和 → i64::MAX 列，无 panic；语义不翻转
    let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
    let mut e = mk_env([1; 32], [5; 16], vec![1], 1000);
    e.recipient = None;
    db.enqueue(&e).unwrap();
    assert!(db.fail_and_reschedule(&[5; 16], &pmax, 0).is_ok(), "delay=u64::MAX 调度不得 panic");
    assert!(db.due(0, 10).unwrap().is_empty(), "饱和的 next_attempt 不得提前到期");
    assert_eq!(db.due(u64::MAX, 10).unwrap().len(), 1, "u64::MAX 时刻必须视为已到期（饱和语义）");
}

/// BucketWrite（线上信封的真实外层）深嵌套 CBOR：与 red12 同一解码器、不同结构体——
/// 10 万层不定长数组必须报错而非递归打爆栈。
#[test]
fn green_g6_bucketwrite_cbor_deep_nesting_rejected_not_stack_overflow() {
    let depth = 100_000usize;
    let mut b = Vec::with_capacity(2 * depth + 8);
    b.push(0xA1); // map(1)
    b.push(0x61);
    b.push(b'q'); // 未知键 → IgnoredAny
    for _ in 0..depth {
        b.push(0x9F);
    }
    for _ in 0..depth {
        b.push(0xFF);
    }
    let r = BucketWrite::from_cbor(&b);
    assert!(r.is_err(), "RED: BucketWrite 深嵌套未被拒绝");
    println!("[g6] depth=100k → {:?}", r.err());
}

/// 设置文件毒化：非法 JSON / NaN 字面量 / 错误类型 → 回退默认（fail-closed）；
/// 极端但合法的阈值（全 0 / u32::MAX）被接受后，自适应引擎契约（升档即时、降档逐级）仍成立。
#[test]
fn green_g7_settings_poison_fails_closed_engine_contract_holds() {
    let dir = std::env::temp_dir().join(format!("dc-adv-g7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("settings.json");

    std::fs::write(&file, r#"{"adaptive":{"enabled":true,"thresholds":{"group_medium":0,"rate_medium":0.0,"demote_samples":0}},"bluetooth_switch_seconds":4294967295,"strict_crypto":false}"#).unwrap();
    let s = Settings::load_or_default(&dir);
    assert_eq!(s.adaptive.thresholds.group_medium, 0, "合法极端值按用户配置接受");

    let mut e = PolicyEngine::new(s.adaptive.thresholds.clone());
    assert_eq!(e.observe(Metrics { group_size: u32::MAX, msg_rate: f32::MAX }), Tier::Heavy);
    assert_eq!(e.observe(Metrics { group_size: 0, msg_rate: 0.0 }), Tier::Medium, "demote_samples=0 仍逐级降");
    assert_eq!(e.observe(Metrics { group_size: 0, msg_rate: 0.0 }), Tier::Light, "Heavy→Medium→Light 逐级");

    std::fs::write(&file, r#"{"adaptive":{"thresholds":{"rate_medium":NaN}}}"#).unwrap();
    assert_eq!(Settings::load_or_default(&dir), Settings::default(),
        "RED: NaN 字面量文件未回退默认（fail-closed 破口）");
    std::fs::write(&file, r#"{"bluetooth_switch_seconds":"ten"}"#).unwrap();
    assert_eq!(Settings::load_or_default(&dir), Settings::default(), "类型毒化必须整体回退默认");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 内部钟极端输入（A10 溢出点之外的饱和覆盖面）：四时间戳全 i64::MIN/MAX 组合、
/// now(-1)/now(i64::MAX)、source() 极值——饱和运算兜底，输出保持非负、无 panic。
#[test]
fn green_g8_clock_extreme_inputs_bounded() {
    let mut c = InternalClock::new();
    c.trust_peer([1; 32]);
    let combos: [(i64, i64, i64, i64); 4] = [
        (i64::MIN, i64::MAX, i64::MAX, i64::MAX),
        (0, i64::MAX, i64::MAX, i64::MIN),
        (i64::MIN, 0, 1, i64::MIN),
        (i64::MAX, i64::MAX, i64::MIN, i64::MAX),
    ];
    for (t1, t2, t3, t4) in combos {
        let r = c.on_peer_exchange([1; 32], t1, t2, t3, t4);
        let _ = r; // Ok/Err 均可——只要不 panic、不产生越界偏移
        if let Ok(off) = r {
            assert!(off.abs() <= 24 * 60 * 60 * 1000, "RED: 偏移越出 ±24h 限幅: {off}");
        }
    }
    assert_eq!(c.now(-1), 0, "负本地钟 → 内部钟钳 0（非负域）");
    assert!(c.now(i64::MAX) > 0);
    let _ = c.source(i64::MAX);
    assert_eq!(c.source(i64::MAX), Source::Unsynced, "无校准源时 source 恒为 Unsynced（不 panic 即达成本测试目的）");
    // 高水位单调性在极端往返下保持
    let hw = c.high_water_ms();
    let again = c.now(i64::MAX - 60_000);
    assert!(again as u64 >= hw, "RED: 内部钟高水位回退");
}

/// 测试支撑：NodeKeyAnnouncement 的 signing_payload 是私有的——
/// G4 的倒挂窗条目需要合法签名来隔离「签名校验」与「窗口校验」两层。
trait SigningPayload {
    fn signing_payload_pub(&self) -> Vec<u8>;
}
impl SigningPayload for NodeKeyAnnouncement {
    fn signing_payload_pub(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(112);
        v.extend_from_slice(b"dc-node-key-announcement-v1\n");
        v.extend_from_slice(&self.identity);
        v.extend_from_slice(&self.node_key);
        v.extend_from_slice(&self.serial.to_be_bytes());
        v.extend_from_slice(&self.not_before_ms.to_be_bytes());
        v.extend_from_slice(&self.not_after_ms.to_be_bytes());
        v
    }
}
