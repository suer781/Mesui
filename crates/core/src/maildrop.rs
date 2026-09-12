//! 信箱写桶管理器（SP-1 第 5 条的最后一环：按写入方限速）。
//!
//! 把 `mailbox.rs` 已有的入站验收顺序（MAC → 时间窗 → msg_id 去重，
//! 由 `verify_inbound()` 在代码里强制）与「按写入方限速」接成单一入口，
//! 供中继/收件方在入桶前调用。Ok = 可入桶，实际存储由调用方处理。
//!
//! 读桶路径（SP-1.6）：`BucketStorage` 存储抽象（内存实现，生产由 Kotlin
//! 侧 SQLCipher 替换）+ `MailboxManager::read_bucket`（读取 MAC 鉴权 →
//! nonce 台账防重放读 → 按游标取）。
//!
//! 与 `governor.rs` 的分工：RelayGovernor 治理**陌生人转发份额**（算力
//! 公平分配），本模块治理**联系人信箱写入频率**（SP-1 风控限额，
//! 默认 ≤30 封/分钟/对），两者互不替代。
//!
//! 公告分发（SP-2.3）：`distribute_announcement` 把签名节点密钥公告作为
//! SessionMgmt 信封经联系人信箱桶推送——公告**不加密**（自带长期身份
//! 签名，收方 `NodeKeyRing::upsert` 验签），中继只验信箱 MAC、不解内文。
//!
//! 线程模型：MailboxManager 字段全部 Send + Sync（编译期钉死），自身
//! 不加锁；FFI 层用 `std::sync::Mutex` 包装（见 ffi::MailboxManagerHandle），
//! Android 侧多线程经 UniFFI Object 的 &self 并发进入时串行化。

use crate::envelope::{Envelope, PayloadKind};
use crate::identity::NodeId;
use crate::mailbox::{verify_inbound, BucketWrite, MailboxRead, NonceCache};
use crate::nodekey::NodeKeyAnnouncement;
use crate::CoreError;
use std::collections::HashMap;

/// 每对（发送方 → 本桶）每分钟写入上限（SP-1 第 5 条默认值）。
pub const WRITES_PER_MINUTE: u32 = 30;

/// 令牌桶容量 = 每分钟上限（允许一次小突发，与 governor.rs 同思路）。
const BUCKET_CAPACITY: f64 = WRITES_PER_MINUTE as f64;
/// 补充速率：30 token / 60_000 ms。
const REFILL_PER_MS: f64 = BUCKET_CAPACITY / 60_000.0;

/// 发送方闲置多久后可从限速表驱逐：该时长内桶必然已回满
/// （回满只需 60s，取 2 倍裕量），驱逐后再进 = 满桶起步，
/// 不给任何超额写权——驱逐本身不可用来刷限额。
const SENDER_IDLE_EVICT_MS: u64 = 2 * 60_000;
/// 限速表软上限：超过才触发闲置清扫（正常联系人规模远达不到），
/// 防止表随「被 MAC 放行的写入方数量」无界增长。
const SENDER_SOFT_CAP: usize = 4096;

/// 信箱写桶门禁错误。刻意与 CoreError 分离：这是协议层判定结果，
/// UI/调用方要按种类区别处置（重放 ≠ 限速 ≠ 篡改 ≠ 时钟漂移）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    /// MAC 验签不过（钥匙不符或内容被篡改）——门口拒绝。
    MacMismatch,
    /// 发送方时间戳超出 ±5 分钟重放窗。
    WindowExceeded,
    /// msg_id 台账命中：同一写已在窗内验收过（重放）。
    ReplayRejected,
    /// 该发送方超过每分钟写入上限（令牌桶无余量）。
    RateLimited,
    /// 读桶存储层故障（库打不开/查询失败等）——非协议判定，
    /// 与「无权限」区分：前者可重试，后者必须拒绝。
    Storage(String),
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailboxError::MacMismatch => f.write_str("信箱验签失败（钥匙不符或内容被篡改）"),
            MailboxError::WindowExceeded => f.write_str("信箱写入时间戳超出重放窗口"),
            MailboxError::ReplayRejected => f.write_str("重放的信箱请求被拒绝"),
            MailboxError::RateLimited => f.write_str("发送方写入超过限速（≤30 封/分钟/对）"),
            MailboxError::Storage(e) => write!(f, "读桶存储错误: {e}"),
        }
    }
}

impl std::error::Error for MailboxError {}

/// 把 `mailbox::verify_inbound` 的 CoreError 映射为分类错误。
///
/// mailbox.rs 的失败文案是本 crate 内的稳定字面量
/// （"mailbox mac mismatch" / "mailbox write outside replay window" /
/// "replayed write"），此处按文案归类；未知文案按篡改处理（fail-closed）。
/// 文案若被改动，下方 maildrop 测试会立即失败。
fn classify_gate(e: crate::CoreError) -> MailboxError {
    match e {
        crate::CoreError::Crypto(msg) => {
            if msg.contains("replayed write") {
                MailboxError::ReplayRejected
            } else if msg.contains("outside replay window") {
                MailboxError::WindowExceeded
            } else {
                MailboxError::MacMismatch
            }
        }
        _ => MailboxError::MacMismatch,
    }
}

/// 桶存储抽象（SP-1.6 读路径）：写路径经验收后入库，读路径经鉴权后按游标取。
/// 生产实现 = Kotlin 侧 SQLCipher（同库同钥的独立表）替换本 trait；
/// 序号语义：`store` 返回桶内序号（从 1 起单调递增），cursor = 已读到的
/// 序号，`fetch_after` 返回序号 > cursor 的消息（升序，空桶/越界 = 空表）。
pub trait BucketStorage: Send + Sync {
    fn store(&self, bucket: &[u8; 32], write: &BucketWrite) -> Result<u64, CoreError>;
    fn fetch_after(&self, bucket: &[u8; 32], cursor: u64) -> Result<Vec<BucketWrite>, CoreError>;
    fn count(&self, bucket: &[u8; 32]) -> Result<u64, CoreError>;
}

/// 内存实现（HashMap + Mutex）：测试/演示用，进程退出即丢。
/// 内部持锁保证 Send + Sync，可被任意线程经 `&dyn BucketStorage` 并发访问。
#[derive(Default)]
pub struct InMemoryBucketStorage {
    buckets: std::sync::Mutex<HashMap<[u8; 32], Vec<BucketWrite>>>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemoryBucketStorage>();
};

impl BucketStorage for InMemoryBucketStorage {
    fn store(&self, bucket: &[u8; 32], write: &BucketWrite) -> Result<u64, CoreError> {
        let mut buckets = self.buckets.lock().expect("bucket storage mutex poisoned");
        let v = buckets.entry(*bucket).or_default();
        v.push(write.clone());
        Ok(v.len() as u64) // 序号 = 入库顺序（从 1 起）
    }

    fn fetch_after(&self, bucket: &[u8; 32], cursor: u64) -> Result<Vec<BucketWrite>, CoreError> {
        let buckets = self.buckets.lock().expect("bucket storage mutex poisoned");
        let v = buckets.get(bucket).map(Vec::as_slice).unwrap_or(&[]);
        // 序号 = index + 1：「序号 > cursor」⟺「index ≥ cursor」；
        // 越界游标（> 桶长）钳到桶长 = 返回空（读尽语义，不是错误）
        let start = (cursor as usize).min(v.len());
        Ok(v[start..].to_vec())
    }

    fn count(&self, bucket: &[u8; 32]) -> Result<u64, CoreError> {
        let buckets = self.buckets.lock().expect("bucket storage mutex poisoned");
        Ok(buckets.get(bucket).map_or(0, |v| v.len() as u64))
    }
}

// ══════════ SP-2.3 公告分发：节点密钥轮换公告经联系人信箱桶推送 ══════════

/// 公告信封的跳数预算：与普通消息同路（联系人信箱推送，不经多跳转发）。
const ANNOUNCEMENT_TTL_HOPS: u8 = 6;
/// 公告写使用的 mailbox secret 版本：调用方传入的即当前版本 secret
/// （与 `MailboxRead::seal_read` 默认 serial=1 一致；版本协商属握手层，
/// 未来需要时再扩参）。
const ANNOUNCEMENT_MAILBOX_SERIAL: u32 = 1;

/// 分发内核：验签 → 公告 CBOR → SessionMgmt 信封 → 按 bucket_secret 密封信箱 MAC。
/// 公告**不加密**：自带长期身份签名（收方 upsert 验签），中继只验信箱 MAC、
/// 不解内文（SP-2.3）。验签前置 = 拒发未签名/被篡改的公告（fail-closed：分发即背书）。
pub fn seal_announcement_write(
    ann: &NodeKeyAnnouncement,
    bucket_secret: &[u8; 32],
    now_ms: u64,
) -> Result<BucketWrite, CoreError> {
    ann.verify()?;
    let body = ann.to_cbor()?;
    let mut msg_id = [0u8; 16];
    getrandom::fill(&mut msg_id).map_err(|e| CoreError::Entropy(e.to_string()))?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| CoreError::Entropy(e.to_string()))?;
    let env = Envelope {
        msg_id,
        // 联系人信箱路径语义：sender = 长期身份公钥（收件方可验）
        sender: ann.identity,
        recipient: None,
        group: None,
        kind: PayloadKind::SessionMgmt,
        body,
        sent_at_ms: now_ms,
        ttl_hops: ANNOUNCEMENT_TTL_HOPS,
    };
    Ok(BucketWrite::seal(
        env,
        bucket_secret,
        ANNOUNCEMENT_MAILBOX_SERIAL,
        now_ms,
        nonce,
    ))
}

/// 公告分发（SP-2.3）：把签名公告作为 SessionMgmt 信封写入联系人信箱桶。
/// 收方在信箱读路径验 MAC 后解 CBOR → `NodeKeyRing::upsert`
/// （验签 + 30 天有效期 + 过渡窗语义）。
pub fn distribute_announcement(
    ann: &NodeKeyAnnouncement,
    bucket_secret: &[u8; 32],
    storage: &mut dyn BucketStorage,
    bucket: &[u8; 32],
    now_ms: u64,
) -> Result<(), CoreError> {
    let write = seal_announcement_write(ann, bucket_secret, now_ms)?;
    storage.store(bucket, &write)?;
    Ok(())
}

/// 每发送方的令牌桶：容量 = 每分钟上限，按流逝时间线性补充。
#[derive(Debug, Clone)]
struct SenderRate {
    tokens: f64,
    last_refill_ms: u64,
}

impl SenderRate {
    /// 首见的发送方满桶起步。
    fn new(now_ms: u64) -> Self {
        Self { tokens: BUCKET_CAPACITY, last_refill_ms: now_ms }
    }

    /// 尝试取 1 个令牌；返回是否放行。时钟回拨只停止补充、不倒扣
    /// （saturating 语义：不产生负时间差）。
    fn try_take(&mut self, now_ms: u64) -> bool {
        if now_ms > self.last_refill_ms {
            let elapsed = now_ms - self.last_refill_ms;
            self.tokens = (self.tokens + elapsed as f64 * REFILL_PER_MS).min(BUCKET_CAPACITY);
            self.last_refill_ms = now_ms;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn idle_for(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_refill_ms)
    }
}

/// 信箱管理器：msg_id 去重台账（NonceCache）+ 按写入方限速表。
///
/// 每个实例服务一个桶（一对联系人一个 secret）；跨桶复用同一实例也
/// 安全——去重键是 128 位随机 msg_id，限速键是发送方 NodeId，互不串扰。
pub struct MailboxManager {
    nonces: NonceCache,
    /// 红队 A2b Verifier 修复：读 nonce 独立台账——**不过期**（只 FIFO 驱逐），
    /// 读路径无时间窗，nonce 条目若过期则同请求重放可拉取新到密文（元数据泄露）。
    read_nonces: std::collections::HashSet<[u8; 32]>,
    read_order: std::collections::VecDeque<[u8; 32]>,
    /// 读 nonce 台账容量（≈800KB 内存 @16384 条 × ~48B/条）
    read_cap: usize,
    senders: HashMap<NodeId, SenderRate>,
}

// Android 侧多线程经 FFI 并发调用：编译期钉死 Send + Sync。
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MailboxManager>();
};

impl MailboxManager {
    /// `cap` = msg_id 去重台账软目标容量（实际下限 4096，满则 fail-closed）。
    pub fn new(cap: usize) -> Self {
        Self {
            nonces: NonceCache::new(cap),
            read_nonces: std::collections::HashSet::new(),
            read_order: std::collections::VecDeque::new(),
            read_cap: (cap.max(4096)).max(16384),
            senders: HashMap::new(),
        }
    }

    /// 信箱写桶完整验收（SP-1 第 3/5 条顺序，代码强制不可重排）：
    /// 1. MAC（常量时间比较）→ 2. ±5min 时间窗 → 3. msg_id 去重
    ///    ——以上三步由 `verify_inbound()` 强制，去重必须后于验签
    ///    （防用重复响应探测 msg_id 存在性）；
    /// 4. 按写入方限速（令牌桶，≤30 封/分/对，超限拒绝）。
    ///
    /// 返回 Ok 表示「可入桶」，实际存储由调用方处理。
    /// 注意：步骤 3 已把该写记入台账，被限速的写重交同一份会得到
    /// ReplayRejected 而非 RateLimited——这是刻意的（拒绝重探）。
    pub fn submit_write(
        &mut self,
        write: &BucketWrite,
        secret: &[u8; 32],
        now_ms: u64,
    ) -> std::result::Result<(), MailboxError> {
        verify_inbound(write, secret, &mut self.nonces, now_ms).map_err(classify_gate)?;
        self.rate_limit(&write.envelope.sender, now_ms)?;
        Ok(())
    }

    /// 信箱读桶验收（SP-1.6 读路径；顺序与写路径镜像，代码强制不可重排）：
    /// 1. 读取 MAC（常量时间比较）——读取**无时间窗**（±5min 只限写入）；
    /// 2. nonce 台账防重放读——**独立台账，不过期**（红队 A2b Verifier 修复：
    ///    读路径无时间窗，共享写台账的过期语义会让 ~9 分钟后重放复活）。
    ///    FIFO 驱逐在容量上限时才触发（16384 条 ≈ 800KB，移动端可承受）；
    ///    台账必须后于鉴权：与写同理，防用重复响应探测请求有效性；
    /// 3. 从 storage 取桶内序号 > cursor 的消息（升序；空桶/读尽 = 空表）。
    ///
    /// 需要 &mut self：nonce 台账在放行时记账（check_and_insert）。
    /// 读路径不进写入限速表（限速键是发送方 NodeId，与读无关）。
    pub fn read_bucket(
        &mut self,
        read: &MailboxRead,
        secret: &[u8; 32],
        storage: &dyn BucketStorage,
        _now_ms: u64,
    ) -> std::result::Result<Vec<BucketWrite>, MailboxError> {
        read.verify_read(secret, _now_ms).map_err(classify_gate)?;
        // 读 nonce 独立台账：FIFO 驱逐（无时间过期），键 = nonce 128 位
        let key: [u8; 32] = crate::identity::fingerprint1024(&[b"read-nonce", &read.nonce])[..32]
            .try_into()
            .unwrap();
        if !self.read_nonces.insert(key) {
            return Err(MailboxError::ReplayRejected);
        }
        self.read_order.push_back(key);
        while self.read_order.len() > self.read_cap {
            if let Some(old) = self.read_order.pop_front() {
                self.read_nonces.remove(&old);
            }
        }
        storage
            .fetch_after(&read.bucket, read.cursor)
            .map_err(|e| MailboxError::Storage(e.to_string()))
    }

    fn rate_limit(&mut self, sender: &NodeId, now_ms: u64) -> std::result::Result<(), MailboxError> {
        // 软上限触发闲置清扫：限速表不随写入方数量无界增长
        if self.senders.len() >= SENDER_SOFT_CAP {
            self.senders.retain(|_, r| r.idle_for(now_ms) < SENDER_IDLE_EVICT_MS);
        }
        let rate = self.senders.entry(*sender).or_insert_with(|| SenderRate::new(now_ms));
        if rate.try_take(now_ms) {
            Ok(())
        } else {
            Err(MailboxError::RateLimited)
        }
    }

    /// 去重台账当前条数（监控/测试用）。
    pub fn nonce_cache_len(&self) -> usize {
        self.nonces.len()
    }

    /// 限速表当前跟踪的发送方数（监控/测试用）。
    pub fn tracked_senders(&self) -> usize {
        self.senders.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, PayloadKind};
    use crate::identity::Identity;
    use crate::mailbox::{derive_mailbox_secret, generate_bucket_address, REPLAY_WINDOW_MS};

    fn sealed_write(sender: &Identity, secret: &[u8; 32], byte: u8, ts_ms: u64) -> BucketWrite {
        let env = Envelope {
            msg_id: [byte; 16],
            sender: sender.node_id(),
            recipient: Some([9; 32]),
            group: None,
            kind: PayloadKind::Text,
            body: vec![7; 64],
            sent_at_ms: ts_ms,
            ttl_hops: 6,
        };
        BucketWrite::seal(env, secret, 1, ts_ms, [byte; 16])
    }

    fn fresh_manager() -> MailboxManager {
        MailboxManager::new(4096)
    }

    #[test]
    fn submit_write_accepts_fresh_write() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let ts = 1_000_000u64;
        let w = sealed_write(&sender, &secret, 1, ts);
        mgr.submit_write(&w, &secret, ts).unwrap();
        // 台账记 1 条、限速表跟踪 1 个发送方
        assert_eq!(mgr.nonce_cache_len(), 1);
        assert_eq!(mgr.tracked_senders(), 1);
    }

    #[test]
    fn submit_write_rejects_replay() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let ts = 1_000_000u64;
        let w = sealed_write(&sender, &secret, 7, ts);
        mgr.submit_write(&w, &secret, ts).unwrap();
        // 同一写（同 nonce 同 msg_id）再交：MAC/窗都过，台账命中
        assert_eq!(mgr.submit_write(&w, &secret, ts), Err(MailboxError::ReplayRejected));
        // 换个「当前时刻」重放同 msg_id 一样拒绝（台账键 = msg_id）
        assert_eq!(mgr.submit_write(&w, &secret, ts + 1000), Err(MailboxError::ReplayRejected));
    }

    #[test]
    fn submit_write_rate_limited_after_thirty_per_minute() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let t0 = 10_000_000u64;
        // 30 封全部放行（每封独立 msg_id/nonce）
        for i in 0..WRITES_PER_MINUTE {
            let w = sealed_write(&sender, &secret, (i as u8) + 1, t0);
            mgr.submit_write(&w, &secret, t0).unwrap();
        }
        // 第 31 封：同一时刻无补充，桶空 → 限速
        let w31 = sealed_write(&sender, &secret, 40, t0);
        assert_eq!(mgr.submit_write(&w31, &secret, t0), Err(MailboxError::RateLimited));
        // 61s 后（> 60s 回满期，避开浮点边界）桶回满，且新写 ts 仍在窗内
        let t1 = t0 + 61_000;
        mgr.submit_write(&sealed_write(&sender, &secret, 41, t1), &secret, t1).unwrap();
    }

    #[test]
    fn submit_write_rejects_mac_mismatch() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let ts = 1_000_000u64;
        let w = sealed_write(&sender, &secret, 7, ts);
        // 换钥匙（跨桶/跨版本）
        let wrong = derive_mailbox_secret(b"other-secret", &bucket, 1);
        assert_eq!(mgr.submit_write(&w, &wrong, ts), Err(MailboxError::MacMismatch));
        // 篡改正文同样在 MAC 层拒绝
        let mut tampered = w.clone();
        tampered.envelope.body.push(1);
        assert_eq!(mgr.submit_write(&tampered, &secret, ts), Err(MailboxError::MacMismatch));
        // MAC 拒绝不消耗台账名额：用对钥匙仍可入桶
        mgr.submit_write(&w, &secret, ts).unwrap();
    }

    #[test]
    fn submit_write_rejects_outside_window() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let ts = 10_000_000u64;
        let w = sealed_write(&sender, &secret, 7, ts);
        // 过新（对端时钟被调远）/ 过旧，均超 ±5min 窗
        let future = ts + REPLAY_WINDOW_MS + 1;
        assert_eq!(mgr.submit_write(&w, &secret, future), Err(MailboxError::WindowExceeded));
        let past = ts.saturating_sub(REPLAY_WINDOW_MS + 1);
        assert_eq!(mgr.submit_write(&w, &secret, past), Err(MailboxError::WindowExceeded));
        // 窗外拒绝发生在去重之前，不消耗台账名额：回到窗内仍可入桶
        mgr.submit_write(&w, &secret, ts).unwrap();
    }

    #[test]
    fn senders_have_independent_buckets() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let t0 = 10_000_000u64;
        // A 打满自己的 30 封
        for i in 0..WRITES_PER_MINUTE {
            let w = sealed_write(&a, &secret, (i as u8) + 1, t0);
            mgr.submit_write(&w, &secret, t0).unwrap();
        }
        assert_eq!(
            mgr.submit_write(&sealed_write(&a, &secret, 99, t0), &secret, t0),
            Err(MailboxError::RateLimited)
        );
        // B 的桶独立：A 被限速不影响 B 满额可写
        mgr.submit_write(&sealed_write(&b, &secret, 50, t0), &secret, t0).unwrap();
        // B 打满自己的 30 封（前面已用 1 封）
        for i in 1..WRITES_PER_MINUTE {
            let w = sealed_write(&b, &secret, 60 + (i as u8), t0);
            mgr.submit_write(&w, &secret, t0).unwrap();
        }
        assert_eq!(
            mgr.submit_write(&sealed_write(&b, &secret, 98, t0), &secret, t0),
            Err(MailboxError::RateLimited)
        );
        assert_eq!(mgr.tracked_senders(), 2);
    }

    // ══════════ 读桶（read_bucket + BucketStorage，SP-1.6） ══════════

    fn sealed_read(bucket: [u8; 32], secret: &[u8; 32], cursor: u64, n: u8) -> MailboxRead {
        // 读 nonce 字节错开本测试写的 msg_id 字节（1..=4）：生产中两类键均为
        // 128 位随机、碰撞概率可忽略，但退化常量会在共享台账里假性相撞
        MailboxRead::seal_read(bucket, secret, cursor, [0xB0 + n; 16])
    }

    #[test]
    fn in_memory_storage_store_fetch_count_roundtrip() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let st = InMemoryBucketStorage::default();
        assert_eq!(st.count(&bucket).unwrap(), 0);
        assert!(st.fetch_after(&bucket, 0).unwrap().is_empty(), "空桶取回空");
        // 4 条入库：序号从 1 起单调递增
        let mut seqs = Vec::new();
        for i in 1..=4u8 {
            seqs.push(st.store(&bucket, &sealed_write(&sender, &secret, i, 1_000_000)).unwrap());
        }
        assert_eq!(seqs, vec![1, 2, 3, 4]);
        assert_eq!(st.count(&bucket).unwrap(), 4);
        // 游标语义：cursor=0 全部；cursor=2 只剩第 3、4 条；越界游标返回空
        assert_eq!(st.fetch_after(&bucket, 0).unwrap().len(), 4);
        let tail = st.fetch_after(&bucket, 2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].envelope.msg_id, [3; 16]);
        assert_eq!(tail[1].envelope.msg_id, [4; 16]);
        assert!(st.fetch_after(&bucket, 4).unwrap().is_empty());
        assert!(st.fetch_after(&bucket, 99).unwrap().is_empty());
        // 桶间隔离：另一桶不串数据
        let other = generate_bucket_address().unwrap();
        assert_eq!(st.count(&other).unwrap(), 0);
        assert!(st.fetch_after(&other, 0).unwrap().is_empty());
        // 取回内容保真（线上 CBOR 无损）
        let first = &st.fetch_after(&bucket, 0).unwrap()[0];
        assert_eq!(
            first.to_cbor().unwrap(),
            sealed_write(&sender, &secret, 1, 1_000_000).to_cbor().unwrap()
        );
    }

    #[test]
    fn read_bucket_returns_messages_after_cursor() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let st = InMemoryBucketStorage::default();
        let ts = 1_000_000u64;
        // 生产顺序：写门禁验收 → 入库 → 对方凭 secret 分页读
        for i in 1..=4u8 {
            let w = sealed_write(&sender, &secret, i, ts);
            mgr.submit_write(&w, &secret, ts).unwrap();
            st.store(&bucket, &w).unwrap();
        }
        let senders_before = mgr.tracked_senders();
        // cursor=0：全部 4 条
        let all = mgr.read_bucket(&sealed_read(bucket, &secret, 0, 1), &secret, &st, ts).unwrap();
        assert_eq!(all.len(), 4);
        // cursor=2：只返回第 3、4 条
        let tail = mgr.read_bucket(&sealed_read(bucket, &secret, 2, 2), &secret, &st, ts).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].envelope.msg_id, [3; 16]);
        assert_eq!(tail[1].envelope.msg_id, [4; 16]);
        // cursor=4：读尽返回空（非错误）
        let done = mgr.read_bucket(&sealed_read(bucket, &secret, 4, 3), &secret, &st, ts).unwrap();
        assert!(done.is_empty());
        // 读路径不得进写入限速表（限速只针对写）
        assert_eq!(mgr.tracked_senders(), senders_before, "读桶不得消耗写入限速额度");
        // 空桶：鉴权通过但无消息 → Ok(空)
        let empty = InMemoryBucketStorage::default();
        assert!(
            mgr.read_bucket(&sealed_read(bucket, &secret, 0, 4), &secret, &empty, ts)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn read_bucket_rejects_unauthorized_secret() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let st = InMemoryBucketStorage::default();
        let ts = 1_000_000u64;
        let w = sealed_write(&sender, &secret, 1, ts);
        mgr.submit_write(&w, &secret, ts).unwrap();
        st.store(&bucket, &w).unwrap();
        // 旁观者用自选钥匙封读请求，桶主用自己的 secret 验：MAC 必然失配
        let wrong = derive_mailbox_secret(b"eavesdropper", &bucket, 1);
        assert_eq!(
            mgr.read_bucket(&sealed_read(bucket, &wrong, 0, 1), &secret, &st, ts),
            Err(MailboxError::MacMismatch)
        );
        // MAC 拒绝不消耗 nonce 台账名额：持钥者随后仍可读
        let msgs = mgr.read_bucket(&sealed_read(bucket, &secret, 0, 1), &secret, &st, ts).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn read_bucket_rejects_replayed_read() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut mgr = fresh_manager();
        let st = InMemoryBucketStorage::default();
        let ts = 1_000_000u64;
        for i in 1..=3u8 {
            let w = sealed_write(&sender, &secret, i, ts);
            mgr.submit_write(&w, &secret, ts).unwrap();
            st.store(&bucket, &w).unwrap();
        }
        let r = sealed_read(bucket, &secret, 0, 9);
        mgr.read_bucket(&r, &secret, &st, ts).unwrap();
        // 同一读取请求重放（窗内嗅探的合法请求原样再交，任意「当前时刻」）：
        // nonce 台账命中
        assert_eq!(
            mgr.read_bucket(&r, &secret, &st, ts + 60_000),
            Err(MailboxError::ReplayRejected)
        );
        // 换 nonce（新游标继续分页）：正常放行
        let next = sealed_read(bucket, &secret, 1, 10);
        assert_eq!(mgr.read_bucket(&next, &secret, &st, ts + 60_000).unwrap().len(), 2);
    }
}
