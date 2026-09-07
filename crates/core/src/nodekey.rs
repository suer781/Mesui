//! 节点密钥轮换（风险登记 B2）——模式移植自微信支付平台证书轮换：
//! - 轮换公告由**长期身份密钥**签名（对应微信支付对平台证书的签发担保），
//!   公告里带单调递增 `serial`（对应 `Wechatpay-Serial`）
//! - 新旧密钥并行过渡窗（对应旧证书 5 年有效期的并行接受期）
//! - 联系人侧维护密钥环（key ring），按 serial 选钥匙、按有效期淘汰
//!
//! 语义：`node_key` 是本周期 iroh 节点公钥（拨号地址），与长期身份解耦
//! （A1 决议）。追踪者最多跟到一个过渡窗内的临时节点。

use crate::identity::{verify, Identity, NodeId};
use crate::{CoreError, Result};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 过渡窗默认时长：旧节点密钥在接受期内仍可拨（只读语义），之后淘汰。
pub const DEFAULT_OVERLAP_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 天
/// 公告有效期上限（审计 B3）：身份钥一次失窃不得铸「百年公告」，
/// 且撤销依赖同钥——短有效期天然限制失窃损失窗口。
pub const MAX_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1000; // 30 天
/// 红队 red10 修复：单身份公告缓存上限（防递增 serial 无界吃内存）
pub const MAX_ANNOUNCEMENTS_PER_IDENTITY: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NodeKeyAnnouncement {
    /// 公告签名者 = 长期身份公钥
    pub identity: NodeId,
    /// 本周期的 iroh 节点公钥（拨号地址的锚）
    pub node_key: NodeId,
    /// 单调递增，收方按 serial 判新旧（Wechatpay-Serial 对应物）
    pub serial: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    /// Ed25519 签名（64 字节；serde 对 >32 的定长数组无实现，故用 Vec）
    pub sig: Vec<u8>,
}

impl NodeKeyAnnouncement {
    pub fn new(identity: &NodeId, node_key: &NodeId, serial: u64, now_ms: u64, overlap_ms: u64) -> Self {
        Self {
            identity: *identity,
            node_key: *node_key,
            serial,
            not_before_ms: now_ms,
            not_after_ms: now_ms.saturating_add(overlap_ms),
            sig: Vec::new(),
        }
    }

    /// 规范化签名串：身份、节点钥、版本、有效期，缺一不可。
    fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(112);
        v.extend_from_slice(b"dc-node-key-announcement-v1\n");
        v.extend_from_slice(&self.identity);
        v.extend_from_slice(&self.node_key);
        v.extend_from_slice(&self.serial.to_be_bytes());
        v.extend_from_slice(&self.not_before_ms.to_be_bytes());
        v.extend_from_slice(&self.not_after_ms.to_be_bytes());
        v
    }

    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        if identity.node_id() != self.identity {
            return Err(CoreError::Crypto("announcement signed by wrong identity".into()));
        }
        self.sig = identity.sign(&self.signing_payload()).to_bytes().to_vec();
        Ok(())
    }

    /// 验证签名 + 有效期合法性（not_after 必须晚于 not_before）。
    pub fn verify(&self) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.identity)
            .map_err(CoreError::from)?;
        let sig = Signature::from_bytes(
            self.sig
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Crypto("signature length must be 64".into()))?,
        );
        verify(&vk, &self.signing_payload(), &sig)?;
        if self.not_after_ms <= self.not_before_ms {
            return Err(CoreError::Crypto("invalid validity window".into()));
        }
        if self.not_after_ms.saturating_sub(self.not_before_ms) > MAX_VALIDITY_MS {
            return Err(CoreError::Crypto("validity window exceeds cap".into()));
        }
        if self.serial == 0 {
            return Err(CoreError::Crypto("serial must be positive".into()));
        }
        Ok(())
    }
}

/// 联系人节点密钥环：按身份存各 serial 的公告，按 serial 选钥匙、按过期淘汰。
#[derive(Default)]
pub struct NodeKeyRing {
    entries: HashMap<NodeId, Vec<NodeKeyAnnouncement>>,
}

impl NodeKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// 收到公告：先验签再入环。同 serial 视为重发覆盖；serial 不高于已知的直接丢弃。
    /// 红队 red10 修复：单身份公告数上限——恶意联系人连发递增 serial 的合法公告
    /// 不再能无界吃内存（超出即逐出最旧，最高 serial 始终保留）。
    pub fn upsert(&mut self, ann: &NodeKeyAnnouncement, now_ms: u64) -> Result<()> {
        ann.verify()?;
        if ann.not_after_ms <= now_ms {
            return Err(CoreError::Crypto("announcement already expired".into()));
        }
        let slot = self.entries.entry(ann.identity).or_default();
        if slot.iter().any(|e| e.serial > ann.serial) {
            // 旧公告（乱序到达），丢弃但不算错误
            return Ok(());
        }
        slot.retain(|e| e.serial != ann.serial);
        slot.push(ann.clone());
        // 顺手清理全过期项
        slot.retain(|e| e.not_after_ms > now_ms);
        // 容量上限：保住最高 serial（当前钥），逐出更旧的
        while slot.len() > MAX_ANNOUNCEMENTS_PER_IDENTITY {
            let oldest = slot
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.serial)
                .map(|(i, _)| i);
            match oldest {
                Some(i) if slot[i].serial < ann.serial => {
                    slot.remove(i);
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// 当前应拨的节点密钥：取**最高的未过期 serial**（微信支付同款「按 serial 取钥匙」）。
    pub fn current(&self, identity: &NodeId, now_ms: u64) -> Option<&NodeId> {
        self.entries
            .get(identity)?
            .iter()
            .filter(|e| e.not_before_ms <= now_ms && e.not_after_ms > now_ms)
            .max_by_key(|e| e.serial)
            .map(|e| &e.node_key)
    }

    /// 审计 A2：导出全部公告供持久化（调用方写 SQLCipher/文件）。
    /// 恢复后 serial 单调性由 upsert 的「拒绝低 serial」规则天然维持。
    pub fn state(&self) -> Vec<NodeKeyAnnouncement> {
        self.entries.values().flatten().cloned().collect()
    }

    /// 从持久层恢复：每条公告先验签再入环（防持久层被篡改注入伪造公告）。
    pub fn restore(&mut self, entries: Vec<NodeKeyAnnouncement>, now_ms: u64) -> Result<()> {
        for ann in entries {
            self.upsert(&ann, now_ms)?;
        }
        Ok(())
    }

    /// 过渡窗语义：旧 serial 在其 not_after 之前仍可拨（对端尚未切换时的兼容）。
    pub fn accepts(&self, identity: &NodeId, node_key: &NodeId, now_ms: u64) -> bool {
        self.entries
            .get(identity)
            .map(|slot| {
                slot.iter()
                    .any(|e| &e.node_key == node_key && e.not_before_ms <= now_ms && e.not_after_ms > now_ms)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ann(serial: u64, now: u64) -> (Identity, NodeKeyAnnouncement) {
        let id = Identity::generate().unwrap();
        let node = Identity::generate().unwrap();
        let mut ann = NodeKeyAnnouncement::new(&id.node_id(), &node.node_id(), serial, now, DEFAULT_OVERLAP_MS);
        ann.sign(&id).unwrap();
        (id, ann)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (_, ann) = make_ann(1, 1000);
        ann.verify().unwrap();
    }

    #[test]
    fn tamper_rejected() {
        let (_, mut ann) = make_ann(1, 1000);
        ann.node_key = [9; 32];
        assert!(ann.verify().is_err());
        let (_, mut ann2) = make_ann(1, 1000);
        ann2.not_after_ms = ann2.not_before_ms; // 非法窗口
        assert!(ann2.verify().is_err());
        let (_, mut ann3) = make_ann(0, 1000);
        ann3.serial = 0;
        assert!(ann3.verify().is_err());
    }

    #[test]
    fn ring_picks_highest_serial_and_overlaps() {
        let mut ring = NodeKeyRing::new();
        let (id, ann1) = make_ann(1, 1000);
        let node1 = ann1.node_key;
        let node_key2 = Identity::generate().unwrap().node_id();
        let mut ann2 = NodeKeyAnnouncement::new(&id.node_id(), &node_key2, 2, 2000, DEFAULT_OVERLAP_MS);
        ann2.sign(&id).unwrap();

        ring.upsert(&ann1, 1500).unwrap();
        assert_eq!(ring.current(&id.node_id(), 1500), Some(&node1));

        // 新公告先到：切到 serial 2
        ring.upsert(&ann2, 2500).unwrap();
        assert_eq!(ring.current(&id.node_id(), 2500), Some(&node_key2));
        // 过渡窗内旧钥仍被接受（对端没切完）
        assert!(ring.accepts(&id.node_id(), &node1, 2500));
        // 乱序收到 serial 1 的重发：不回退 current
        ring.upsert(&ann1, 2600).unwrap();
        assert_eq!(ring.current(&id.node_id(), 2600), Some(&node_key2));
        // 过渡窗后旧钥淘汰
        assert!(!ring.accepts(&id.node_id(), &node1, 2000 + DEFAULT_OVERLAP_MS + 1));
    }

    #[test]
    fn expired_announcement_rejected() {
        let (_, ann) = make_ann(1, 1000);
        let mut ring = NodeKeyRing::new();
        assert!(ring.upsert(&ann, 1000 + DEFAULT_OVERLAP_MS + 1).is_err());
    }
}
