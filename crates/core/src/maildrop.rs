//! 信箱写桶管理器（SP-1 第 5 条的最后一环：按写入方限速）。
//!
//! 把 `mailbox.rs` 已有的入站验收顺序（MAC → 时间窗 → msg_id 去重，
//! 由 `verify_inbound()` 在代码里强制）与「按写入方限速」接成单一入口，
//! 供中继/收件方在入桶前调用。Ok = 可入桶，实际存储由调用方处理。
//!
//! 与 `governor.rs` 的分工：RelayGovernor 治理**陌生人转发份额**（算力
//! 公平分配），本模块治理**联系人信箱写入频率**（SP-1 风控限额，
//! 默认 ≤30 封/分钟/对），两者互不替代。
//!
//! 线程模型：MailboxManager 字段全部 Send + Sync（编译期钉死），自身
//! 不加锁；FFI 层用 `std::sync::Mutex` 包装（见 ffi::MailboxManagerHandle），
//! Android 侧多线程经 UniFFI Object 的 &self 并发进入时串行化。

use crate::identity::NodeId;
use crate::mailbox::{verify_inbound, BucketWrite, NonceCache};
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
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MailboxError::MacMismatch => "信箱写入验签失败（钥匙不符或内容被篡改）",
            MailboxError::WindowExceeded => "信箱写入时间戳超出重放窗口",
            MailboxError::ReplayRejected => "重放的信箱写入被拒绝",
            MailboxError::RateLimited => "发送方写入超过限速（≤30 封/分钟/对）",
        };
        f.write_str(s)
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
        Self { nonces: NonceCache::new(cap), senders: HashMap::new() }
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
}
