//! 信箱桶门禁：
//! - 每对联系人在 Signal 握手时派生 mailbox secret（本模块输入即握手产物）
//! - 写桶必须附规范化签名串的 MAC + 钥匙版本 serial + 时间戳 + nonce
//! - 中继只验 MAC，不解内容；验签不过 = 在桶门口拒绝，不入库
//! - 防重放：±5 分钟时间窗 + nonce 去重缓存（调用方持有）
//!
//! 本模块只用 keyed-BLAKE3 做认证，不发明任何新原语。

use crate::envelope::Envelope;
use crate::identity::NodeId;
use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// 重放窗口（±5 分钟）。
pub const REPLAY_WINDOW_MS: u64 = 5 * 60 * 1000;

/// 桶地址 = **256 位随机值**（经二维码/介绍信分发）。
/// 不再由身份派生——防止服务方按身份枚举/串联桶。
/// 稳定跨节点密钥轮换（轮换只影响 iroh 拨号地址，不影响桶）；
/// 桶 ID 公开可查存在性，但写入要 MAC、读取要鉴权。
pub fn generate_bucket_address() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|e| CoreError::Entropy(e.to_string()))?;
    Ok(out)
}

/// 由 Signal 握手共享秘密派生某桶某版本的 mailbox secret。
/// 域分隔 + 绑定桶地址 + 密钥版本，防跨桶/跨版本重放同一 MAC。
pub fn derive_mailbox_secret(
    handshake_secret: &[u8],
    bucket: &NodeId,
    serial: u32,
) -> [u8; 32] {
    let mut material = Vec::with_capacity(handshake_secret.len() + 36);
    material.extend_from_slice(handshake_secret);
    material.extend_from_slice(bucket);
    material.extend_from_slice(&serial.to_be_bytes());
    blake3::derive_key("dc-mailbox-v1", &material)
}

/// 一次信箱写入：信封 + 认证包装。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketWrite {
    pub envelope: Envelope,
    /// 钥匙版本：收方按 serial 选 mailbox secret
    pub serial: u32,
    /// 防重放随机数（熵源生成，配合时间窗去重）
    pub nonce: [u8; 16],
    /// 发送方时间戳——仅用于重放窗口（不作任何其他安全判定输入）
    pub ts_ms: u64,
    pub mac: [u8; 32],
}

impl BucketWrite {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| CoreError::Cbor(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|e| CoreError::Cbor(e.to_string()))
    }

    pub fn seal(env: Envelope, secret: &[u8; 32], serial: u32, ts_ms: u64, nonce: [u8; 16]) -> Self {
        let mut w = Self {
            envelope: env,
            serial,
            nonce,
            ts_ms,
            mac: [0u8; 32],
        };
        w.mac = w.compute_mac(secret);
        w
    }

    /// 规范化签名串：
    /// 绑定版本、nonce、时间与**信封全部字段**（此前漏绑
    /// group/kind/sent_at_ms/ttl_hops，recipient=None 时整字段不绑定）。
    fn mac_input(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(160 + self.envelope.body.len());
        v.extend_from_slice(b"dc-bucket-write-v1\n");
        v.extend_from_slice(&self.serial.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ts_ms.to_be_bytes());
        v.extend_from_slice(self.envelope.msg_id.as_slice());
        v.extend_from_slice(&self.envelope.sender);
        // Option 字段带存在标志绑定：None 与「缺字段」可区分
        match &self.envelope.recipient {
            Some(r) => {
                v.push(1);
                v.extend_from_slice(r);
            }
            None => v.push(0),
        }
        match &self.envelope.group {
            Some(g) => {
                v.push(1);
                v.extend_from_slice(g);
            }
            None => v.push(0),
        }
        v.push(self.envelope.kind as u8);
        v.extend_from_slice(&self.envelope.sent_at_ms.to_be_bytes());
        v.push(self.envelope.ttl_hops);
        v.extend_from_slice(&self.envelope.body);
        v
    }

    fn compute_mac(&self, secret: &[u8; 32]) -> [u8; 32] {
        *blake3::Hasher::new_keyed(secret)
            .update(&self.mac_input())
            .finalize()
            .as_bytes()
    }

    /// 中继/收件人侧验证：MAC（常量时间比较）+ 重放窗口。
    /// nonce 去重由调用方查 NonceCache。
    pub fn verify(&self, secret: &[u8; 32], now_ms: u64) -> Result<()> {
        let expected = self.compute_mac(secret);
        let diff = self
            .mac
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(CoreError::Crypto("mailbox mac mismatch".into()));
        }
        let early = self.ts_ms > now_ms.saturating_add(REPLAY_WINDOW_MS);
        let late = self.ts_ms < now_ms.saturating_sub(REPLAY_WINDOW_MS);
        if early || late {
            return Err(CoreError::Crypto("mailbox write outside replay window".into()));
        }
        Ok(())
    }
}

/// 重放防线从「nonce FIFO」改为「msg_id 过期台账」。
/// FIFO 驱逐是可攻击的——窗内合法流量会把旧 nonce 挤出，嗅探重放即复活。
/// 新语义：
/// - 键 = **msg_id**（MAC 已保证其真实性；比 nonce 更有意义的重放标识）
/// - 每条目带过期（写入时刻 + 重放窗 + 偏移容差），**只逐过期条**——
///   窗内的条目永不被驱逐，窗内重放零逃逸
/// - 容量满是 fail-closed：拒绝新写入（可用性损失随窗口自然排空），
///   绝不驱逐未过期防重放状态
/// - 构造参数 = 软目标；攻击_backstop = max(cap, 4096)（约 200KB 内存上界）
/// - 跨重启持久化由调用方负责（与 inbox_seen 同层）
pub struct NonceCache {
    entries: std::collections::HashMap<crate::envelope::MsgId, u64>, // msg_id → expiry_ms
    hard_cap: usize,
}

impl NonceCache {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            hard_cap: cap.max(4096),
        }
    }

    /// true = 首次见到（放行）；false = 重放（拒绝）或容量满（fail-closed）。
    pub fn check_and_insert(&mut self, msg_id: &crate::envelope::MsgId, ts_ms: u64, now_ms: u64) -> bool {
        let expiry = ts_ms.saturating_add(REPLAY_WINDOW_MS + 2 * 60_000);
        // 逐过期条（它们的防重放义务已随窗口终结）
        self.entries.retain(|_, exp| *exp + 2 * 60_000 > now_ms);
        if self.entries.contains_key(msg_id) {
            return false;
        }
        if self.entries.len() >= self.hard_cap {
            return false; // fail-closed：洪泛只换来拒绝，不换来重放
        }
        self.entries.insert(*msg_id, expiry);
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 官方入站流程（顺序在代码里强制，阶段 5 不得自行重排）：
/// 1. MAC 验证 → 2. 时间窗 → 3. nonce 缓存。
///
/// 去重**必须后于**验签——先去重会让攻击者用重复响应探测 msg_id 存在性。
pub fn verify_inbound(
    write: &BucketWrite,
    secret: &[u8; 32],
    nonces: &mut NonceCache,
    now_ms: u64,
) -> Result<()> {
    write.verify(secret, now_ms)?;
    if !nonces.check_and_insert(&write.envelope.msg_id, write.ts_ms, now_ms) {
        return Err(CoreError::Crypto("replayed write".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::PayloadKind;
    use crate::identity::Identity;

    fn sample_envelope(sender: &Identity) -> Envelope {
        Envelope {
            msg_id: [1; 16],
            sender: sender.node_id(),
            recipient: Some([9; 32]),
            group: None,
            kind: PayloadKind::Text,
            body: vec![7; 64],
            sent_at_ms: 0,
            ttl_hops: 6,
        }
    }

    #[test]
    fn cbor_roundtrip_preserves_mac() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let w = BucketWrite::seal(sample_envelope(&sender), &secret, 1, 1000, [6; 16]);
        let bytes = w.to_cbor().unwrap();
        let back = BucketWrite::from_cbor(&bytes).unwrap();
        assert_eq!(w, back);
        // 反序列化后 MAC 仍可验（线上格式无损）
        back.verify(&secret, 1000).unwrap();
    }

    #[test]
    fn seal_verify_roundtrip() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"handshake-abc", &bucket, 1);
        let w = BucketWrite::seal(sample_envelope(&sender), &secret, 1, 1000, [2; 16]);
        w.verify(&secret, 1000 + REPLAY_WINDOW_MS - 1).unwrap();
        w.verify(&secret, 1000).unwrap();
    }

    #[test]
    fn wrong_key_or_tamper_rejected() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut w = BucketWrite::seal(sample_envelope(&sender), &secret, 1, 1000, [3; 16]);

        // 换钥匙（跨桶/跨版本）
        let other = derive_mailbox_secret(b"hs", &bucket, 2);
        assert!(w.verify(&other, 1000).is_err());
        // 篡改正文
        w.envelope.body.push(1);
        assert!(w.verify(&secret, 1000).is_err());
        // 篡改 serial（重放到别的版本）
        let mut w2 = BucketWrite::seal(sample_envelope(&sender), &secret, 1, 1000, [4; 16]);
        w2.serial = 9;
        assert!(w2.verify(&secret, 1000).is_err());
    }

    #[test]
    fn replay_window_enforced() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let ts = 10_000_000u64; // 远大于重放窗口的时间基点
        let w = BucketWrite::seal(sample_envelope(&sender), &secret, 1, ts, [5; 16]);
        // 窗口内通过
        w.verify(&secret, ts).unwrap();
        // 超窗：过旧 / 过新（时钟被调远的设备）
        assert!(w.verify(&secret, ts + REPLAY_WINDOW_MS + 1).is_err());
        assert!(w.verify(&secret, ts - REPLAY_WINDOW_MS - 1).is_err());
    }

    #[test]
    fn nonce_cache_detects_replay_across_serial_space() {
        // 键 = msg_id，条目带过期，只逐过期条
        let mut c = NonceCache::new(1000);
        let id: crate::envelope::MsgId = [9; 16];
        assert!(c.check_and_insert(&id, 1000, 1000));
        assert!(!c.check_and_insert(&id, 1000, 1000), "同 msg_id 重放");
        assert!(!c.check_and_insert(&id, 2000, 2000), "换 serial/时刻重放同 msg_id 也算重放");
        let id2: crate::envelope::MsgId = [8; 16];
        assert!(c.check_and_insert(&id2, 1000, 1000));
    }

    #[test]
    fn mac_binds_every_envelope_field() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let mut e = sample_envelope(&sender);
        e.group = Some([4; 32]);
        let w = BucketWrite::seal(e.clone(), &secret, 1, 1000, [1; 16]);
        w.verify(&secret, 1000).unwrap();
        // 翻转此前未绑定的字段必须破坏 MAC
        let mut w2 = w.clone();
        w2.envelope.kind = PayloadKind::SessionMgmt;
        assert!(w2.verify(&secret, 1000).is_err());
        let mut w3 = w.clone();
        w3.envelope.sent_at_ms += 1;
        assert!(w3.verify(&secret, 1000).is_err());
        let mut w4 = w.clone();
        w4.envelope.ttl_hops -= 1;
        assert!(w4.verify(&secret, 1000).is_err());
        let mut w5 = w.clone();
        w5.envelope.group = None;
        assert!(w5.verify(&secret, 1000).is_err());
    }

    #[test]
    fn derive_binds_bucket_and_serial() {
        let b1 = generate_bucket_address().unwrap();
        let b2 = generate_bucket_address().unwrap();
        assert_ne!(b1, b2, "随机桶地址必须互异");
        assert_ne!(derive_mailbox_secret(b"k", &b1, 1), derive_mailbox_secret(b"k", &b2, 1));
        assert_ne!(derive_mailbox_secret(b"k", &b1, 1), derive_mailbox_secret(b"k", &b1, 2));
        assert_ne!(derive_mailbox_secret(b"k", &b1, 1), derive_mailbox_secret(b"j", &b1, 1));
    }

    #[test]
    fn verify_inbound_enforces_order_and_replay() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"hs", &bucket, 1);
        let w = BucketWrite::seal(sample_envelope(&sender), &secret, 1, 1000, [3; 16]);
        let mut nonces = NonceCache::new(100);
        verify_inbound(&w, &secret, &mut nonces, 1000).unwrap();
        // 重放：nonce 缓存拒绝
        assert!(verify_inbound(&w, &secret, &mut nonces, 1000).is_err());
        // 篡改：MAC 层先拒绝（即便 nonce 是新的）
        let mut bad = w.clone();
        bad.envelope.body.push(1);
        bad.nonce = [9; 16];
        assert!(verify_inbound(&bad, &secret, &mut nonces, 1000).is_err());
    }
}
