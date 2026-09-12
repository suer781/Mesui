//! 节点密钥轮换：
//! - 轮换公告由**长期身份密钥**签名，
//!   公告里带单调递增 `serial`
//! - 新旧密钥并行过渡窗
//! - 联系人侧维护密钥环（key ring），按 serial 选钥匙、按有效期淘汰
//!
//! 语义：`node_key` 是本周期 iroh 节点公钥（拨号地址），与长期身份解耦。
//! 追踪者最多跟到一个过渡窗内的临时节点。

use crate::identity::{verify, Identity, NodeId};
use crate::{CoreError, Result};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 过渡窗默认时长：旧节点密钥在接受期内仍可拨（只读语义），之后淘汰。
pub const DEFAULT_OVERLAP_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 天
/// 公告有效期上限：身份钥一次失窃不得铸「百年公告」，
/// 且撤销依赖同钥——短有效期限制失窃损失窗口。
pub const MAX_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1000; // 30 天
/// 单身份公告缓存上限（防递增 serial 无界吃内存）
pub const MAX_ANNOUNCEMENTS_PER_IDENTITY: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NodeKeyAnnouncement {
    /// 公告签名者 = 长期身份公钥
    pub identity: NodeId,
    /// 本周期的 iroh 节点公钥（拨号地址的锚）
    pub node_key: NodeId,
    /// 单调递增，收方按 serial 判新旧
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

    /// CBOR 线上格式（SP-2.3 分发）：信箱信封 body 即本编码。
    /// serde 用 Vec<u8> 存签名，无定长数组编解码坑。
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(160);
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| CoreError::Cbor(e.to_string()))?;
        Ok(buf)
    }

    /// 从信箱信封 body 还原公告：收方先 from_cbor 再 `NodeKeyRing::upsert`
    /// （内含验签，伪造/被篡改的公告在此被拒）。
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|e| CoreError::Cbor(e.to_string()))
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
    /// 单身份公告数上限——恶意联系人连发递增 serial 的合法公告
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

    /// 当前应拨的节点密钥：取**最高的未过期 serial**。
    pub fn current(&self, identity: &NodeId, now_ms: u64) -> Option<&NodeId> {
        self.entries
            .get(identity)?
            .iter()
            .filter(|e| e.not_before_ms <= now_ms && e.not_after_ms > now_ms)
            .max_by_key(|e| e.serial)
            .map(|e| &e.node_key)
    }

    /// 导出全部公告供持久化（调用方写 SQLCipher/文件）。
    /// 恢复后 serial 单调性由 upsert 的「拒绝低 serial」规则维持。
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

/// 公告分发器（SP-2.3 发送侧）：为本端长期身份生成、签名并登记节点密钥
/// 轮换公告。`rotate()` 产出签名公告 → 调用方经
/// [`crate::maildrop::distribute_announcement`] 写入各联系人信箱桶
/// （公告不加密——自带长期身份签名，中继只验信箱 MAC 不解内文）；
/// 联系人侧由 [`NodeKeyRing`] 接收（upsert 验签 → current/accepts）。
///
/// serial 从 1 起单调递增（0 会被验签拒绝）；密钥环同时服务本端视图
/// （`current_key` / `ring().accepts` 的过渡窗语义）与持久化（`ring().state()`）。
#[derive(Default)]
pub struct AnnouncementDispatcher {
    ring: NodeKeyRing,
    current_serial: u64,
}

impl AnnouncementDispatcher {
    pub fn new() -> Self {
        Self {
            ring: NodeKeyRing::new(),
            current_serial: 0,
        }
    }

    /// 轮换节点密钥：serial 单调 +1 → 新公告 → 长期身份签名 → 入环。
    /// 返回签名公告给调用方去分发（联系人信箱推送，SP-2.3）。
    /// 入环走 `upsert`（内含验签），保证本端视图与分发出去的内容一致。
    pub fn rotate(
        &mut self,
        identity: &Identity,
        new_node_key: &NodeId,
        now_ms: u64,
    ) -> Result<NodeKeyAnnouncement> {
        let serial = self
            .current_serial
            .checked_add(1)
            .ok_or_else(|| CoreError::Crypto("announcement serial exhausted".into()))?;
        let mut ann = NodeKeyAnnouncement::new(
            &identity.node_id(),
            new_node_key,
            serial,
            now_ms,
            DEFAULT_OVERLAP_MS,
        );
        ann.sign(identity)?;
        self.ring.upsert(&ann, now_ms)?;
        self.current_serial = serial;
        Ok(ann)
    }

    /// 当前应拨的节点密钥（委托密钥环：最高未过期 serial）。
    pub fn current_key(&self, identity: &NodeId, now_ms: u64) -> Option<&NodeId> {
        self.ring.current(identity, now_ms)
    }

    /// 只读访问密钥环（过渡窗判定 / 持久化导出共用同一类型）。
    pub fn ring(&self) -> &NodeKeyRing {
        &self.ring
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

    // ══════════ SP-2.3 分发（AnnouncementDispatcher + 信箱推送路径） ══════════

    use crate::envelope::PayloadKind;
    use crate::mailbox::{derive_mailbox_secret, generate_bucket_address};
    use crate::maildrop::{distribute_announcement, BucketStorage, InMemoryBucketStorage};

    /// 端到端：轮换 → 分发进联系人桶 → 对端读桶验 MAC → upsert → current = 新钥。
    #[test]
    fn rotate_distribute_peer_upsert_current_end_to_end() {
        let alice = Identity::generate().unwrap();
        let mut dispatcher = AnnouncementDispatcher::new();
        let t0 = 10_000_000u64;
        let k1 = Identity::generate().unwrap().node_id();

        let ann = dispatcher.rotate(&alice, &k1, t0).unwrap();
        assert_eq!(ann.serial, 1);

        // 分发：写入 bob 的联系人信箱桶（双方经握手共享的 mailbox secret）
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"sp2", &bucket, 1);
        let mut storage = InMemoryBucketStorage::default();
        distribute_announcement(&ann, &secret, &mut storage, &bucket, t0).unwrap();

        // bob 侧收信：读桶 → 中继语义只验 MAC（不解内文）→ 解 CBOR → 入环
        let writes = storage.fetch_after(&bucket, 0).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].envelope.kind, PayloadKind::SessionMgmt);
        writes[0].verify(&secret, t0).unwrap();
        let received = NodeKeyAnnouncement::from_cbor(&writes[0].envelope.body).unwrap();
        assert_eq!(received, ann, "信封 body 的 CBOR 必须无损还原公告");

        let mut peer_ring = NodeKeyRing::new();
        peer_ring.upsert(&received, t0).unwrap();
        assert_eq!(peer_ring.current(&alice.node_id(), t0), Some(&k1));
        // 分发端自身视图同步可见
        assert_eq!(dispatcher.current_key(&alice.node_id(), t0), Some(&k1));
    }

    /// 旧票过渡窗：二次轮换分发后，对端 current 已切新钥、旧钥仍在过渡窗 accepts。
    #[test]
    fn distributed_rotation_keeps_old_key_acceptable_in_overlap() {
        let alice = Identity::generate().unwrap();
        let mut dispatcher = AnnouncementDispatcher::new();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"sp2-overlap", &bucket, 1);
        let mut storage = InMemoryBucketStorage::default();
        let mut peer_ring = NodeKeyRing::new();
        let t0 = 10_000_000u64;

        // 第 1 次轮换：bob 记下旧钥 k1
        let k1 = Identity::generate().unwrap().node_id();
        let ann1 = dispatcher.rotate(&alice, &k1, t0).unwrap();
        distribute_announcement(&ann1, &secret, &mut storage, &bucket, t0).unwrap();

        // 第 2 次轮换（过渡窗起点 t1）
        let t1 = t0 + 1000;
        let k2 = Identity::generate().unwrap().node_id();
        let ann2 = dispatcher.rotate(&alice, &k2, t1).unwrap();
        assert_eq!(ann2.serial, 2);
        distribute_announcement(&ann2, &secret, &mut storage, &bucket, t1).unwrap();

        // bob 按序收两条公告
        for w in storage.fetch_after(&bucket, 0).unwrap() {
            peer_ring
                .upsert(&NodeKeyAnnouncement::from_cbor(&w.envelope.body).unwrap(), t1)
                .unwrap();
        }
        // current 已切新钥；过渡窗内旧钥仍 accepts（对端未切换完的兼容期）
        assert_eq!(peer_ring.current(&alice.node_id(), t1), Some(&k2));
        assert!(peer_ring.accepts(&alice.node_id(), &k1, t1));
        // 过渡窗结束：旧钥淘汰
        assert!(!peer_ring.accepts(&alice.node_id(), &k1, ann1.not_after_ms + 1));
        // 分发端密钥环同样保留过渡窗语义
        assert!(dispatcher.ring().accepts(&alice.node_id(), &k1, t1));
        assert_eq!(dispatcher.current_key(&alice.node_id(), t1), Some(&k2));
    }

    /// 伪造公告：分发端验签拒发；即便攻击者绕过分发端强行写桶，收方 upsert 仍验签拒绝。
    #[test]
    fn forged_announcement_rejected_at_dispatch_and_upsert() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let t0 = 10_000_000u64;
        // 冒充 alice：身份字段填 alice、签名用 mallory 的钥匙现造（必不过验签）
        let mut forged =
            NodeKeyAnnouncement::new(&alice.node_id(), &[7; 32], 1, t0, DEFAULT_OVERLAP_MS);
        forged.sig = mallory.sign(&forged.signing_payload()).to_bytes().to_vec();

        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"sp2-forge", &bucket, 1);
        let mut storage = InMemoryBucketStorage::default();

        // 分发端 fail-closed：验签不过，拒绝写入任何桶
        assert!(distribute_announcement(&forged, &secret, &mut storage, &bucket, t0).is_err());
        assert_eq!(storage.count(&bucket).unwrap(), 0, "伪造公告不得入桶");

        // 纵深防御：Mallory 与 bob 另有信箱关系（能合法写 bob 的桶），把伪造
        // 公告封进信箱写——信箱 MAC 可验（只证明「共享秘密的写入方」），
        // 收方 upsert 仍必须被验签拒绝
        let mut msg_id = [0u8; 16];
        getrandom::fill(&mut msg_id).unwrap();
        let env = crate::envelope::Envelope {
            msg_id,
            sender: mallory.node_id(),
            recipient: None,
            group: None,
            kind: PayloadKind::SessionMgmt,
            body: forged.to_cbor().unwrap(),
            sent_at_ms: t0,
            ttl_hops: 6,
        };
        let w = crate::mailbox::BucketWrite::seal(env, &secret, 1, t0, [3; 16]);
        w.verify(&secret, t0).unwrap();
        storage.store(&bucket, &w).unwrap();
        let relayed = NodeKeyAnnouncement::from_cbor(
            &storage.fetch_after(&bucket, 0).unwrap()[0].envelope.body,
        )
        .unwrap();
        let mut peer_ring = NodeKeyRing::new();
        assert!(peer_ring.upsert(&relayed, t0).is_err(), "伪造公告必须被验签拒绝");
        assert_eq!(peer_ring.current(&alice.node_id(), t0), None);
    }

    /// 连续 3 次轮换：serial 严格递增、current 始终为最新、旧钥过渡窗内仍接受。
    #[test]
    fn three_consecutive_rotations_serial_increments_current_latest() {
        let alice = Identity::generate().unwrap();
        let mut dispatcher = AnnouncementDispatcher::new();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"sp2-three", &bucket, 1);
        let mut storage = InMemoryBucketStorage::default();
        let mut peer_ring = NodeKeyRing::new();
        let t0 = 10_000_000u64;
        let mut prev: Option<NodeKeyAnnouncement> = None;

        for i in 1..=3u64 {
            let now = t0 + (i - 1) * 1000;
            let k = Identity::generate().unwrap().node_id();
            let ann = dispatcher.rotate(&alice, &k, now).unwrap();
            assert_eq!(ann.serial, i, "serial 严格递增");

            // 轮换 → 分发 → 对端收 → current 双侧立即为最新
            distribute_announcement(&ann, &secret, &mut storage, &bucket, now).unwrap();
            let w = &storage.fetch_after(&bucket, i - 1).unwrap()[0];
            peer_ring
                .upsert(&NodeKeyAnnouncement::from_cbor(&w.envelope.body).unwrap(), now)
                .unwrap();
            assert_eq!(peer_ring.current(&alice.node_id(), now), Some(&k));
            assert_eq!(dispatcher.current_key(&alice.node_id(), now), Some(&k));
            if let Some(old) = &prev {
                // 前一把钥在过渡窗内仍被接受
                assert!(peer_ring.accepts(&alice.node_id(), &old.node_key, now));
            }
            prev = Some(ann);
        }
        assert_eq!(storage.count(&bucket).unwrap(), 3);
    }
}
