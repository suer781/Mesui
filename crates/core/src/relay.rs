//! 人群转发票（SP-7 限额陌生人中继）：时间加盐防重放。
//!
//! 威胁：中继者读不到信封内文（无法按 msg_id 去重），嗅探到的合法投递
//! 可被无限重放——每份副本都占用中继的限额与内存，把正规流量挤死。
//!
//! 三重防重放：
//! 1. **逐次握手挑战**：中继先发随机 challenge，票内必须含 challenge 哈希
//!    ——票绑定「这一次」握手，旧票对新握手无效
//! 2. **nonce 票据缓存**：中继按票指纹缓存已收票据，完全相同的票只收一次
//! 3. **过期窗**：expiry 过后一律拒绝（窗口内时钟偏移由 nonce 覆盖）
//!
//! 另有身份伪装防护：票必须由**来源节点密钥**签署——陌生人可以重放旧票，
//! 但造不出带新 challenge/nonce 的新票（没有私钥）。

use crate::identity::{verify, Identity, NodeId};
use crate::{CoreError, Result};

use std::collections::HashMap;

/// 票据有效期上限：人群转发是「活转发」，不给长存储窗口。
pub const MAX_TICKET_TTL_MS: u64 = 2 * 60 * 60 * 1000; // 2 小时

#[derive(Clone, Debug)]
pub struct RelayTicket {
    /// 目的地 = 收件方当前**轮换节点密钥**（陌生人永远见不到长期身份，A1）
    pub dest_node_key: NodeId,
    /// 来源节点密钥（签署者）
    pub origin_node_key: NodeId,
    pub expiry_ms: u64,
    /// 签发时刻（入签，用于强制 TTL ≤ MAX_TICKET_TTL_MS）
    pub issued_at_ms: u64,
    /// 单次盐（每次签发随机）
    pub nonce: [u8; 16],
    /// 中继者本次握手的挑战哈希（时间加盐的「盐」由中继供给）
    pub challenge_hash: [u8; 32],
    pub sig: Vec<u8>,
}

impl RelayTicket {
    pub fn new(
        dest_node_key: &NodeId,
        origin_node_key: &NodeId,
        issued_at_ms: u64,
        expiry_ms: u64,
        nonce: [u8; 16],
        challenge_hash: [u8; 32],
    ) -> Self {
        Self {
            dest_node_key: *dest_node_key,
            origin_node_key: *origin_node_key,
            issued_at_ms,
            expiry_ms,
            nonce,
            challenge_hash,
            sig: Vec::new(),
        }
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(144);
        v.extend_from_slice(b"dc-relay-ticket-v1\n");
        v.extend_from_slice(&self.dest_node_key);
        v.extend_from_slice(&self.origin_node_key);
        v.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        v.extend_from_slice(&self.expiry_ms.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.challenge_hash);
        v
    }

    pub fn sign(&mut self, origin_node_identity: &Identity) -> Result<()> {
        if origin_node_identity.node_id() != self.origin_node_key {
            return Err(CoreError::Crypto("ticket signed by wrong node key".into()));
        }
        self.sig = origin_node_identity.sign(&self.signing_payload()).to_bytes().to_vec();
        Ok(())
    }

    /// 验票：签名 + nonce + TTL 强制（签发→过期 ≤2h）+ 挑战绑定。
    /// `expected_challenge` 是中继本次握手发出的盐——旧票对新握手无效。
    pub fn verify(&self, now_ms: u64, expected_challenge: [u8; 32]) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.origin_node_key)
            .map_err(CoreError::from)?;
        let sig = ed25519_dalek::Signature::from_bytes(
            self.sig
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Crypto("signature length must be 64".into()))?,
        );
        verify(&vk, &self.signing_payload(), &sig)?;
        if self.nonce == [0u8; 16] {
            return Err(CoreError::Crypto("nonce must be random".into()));
        }
        if self.challenge_hash != expected_challenge {
            return Err(CoreError::Crypto("challenge mismatch (stale ticket)".into()));
        }
        // TTL 强制：签发→过期不得超上限（票据是活转发，不给长存储窗口）
        if self.expiry_ms.saturating_sub(self.issued_at_ms) > MAX_TICKET_TTL_MS {
            return Err(CoreError::Crypto("ticket ttl exceeds cap".into()));
        }
        // 红队 red3 修复：未来生效的票（issued_at ≫ now）不得占用缓存槽
        let skew = 2 * 60 * 1000;
        if self.issued_at_ms > now_ms + skew {
            return Err(CoreError::Crypto("ticket issued in the future".into()));
        }
        // 过期窗：窗口留 2 分钟时钟偏移容差，超窗即拒
        if self.expiry_ms + skew < now_ms {
            return Err(CoreError::Crypto("ticket expired".into()));
        }
        Ok(())
    }

    /// 票指纹：去重缓存的键（内容定，与传输无关）
    fn fingerprint(&self) -> [u8; 32] {
        let fp = crate::identity::fingerprint1024(&[b"relay-ticket", &self.signing_payload()]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&fp[..32]);
        out
    }
}

/// 中继侧防重放闸门：票据缓存按过期时间逐出（**永不整体清空**——防灌满重放），
/// 含挑战绑定与基础限额。P0 修复后无独立计数簿记——来源占用数从 seen 现算，
/// 永不与实际状态失同步。
/// 红队 red2 修复：缓存值含**挑战哈希**——旧挑战的条目已不可能通过 verify
/// （纯死重），accept 时优先逐出它们，当前挑战的活条目尽量保全。
pub struct RelayGuard {
    seen: HashMap<[u8; 32], (u64, NodeId, [u8; 32])>, // 票指纹 → (expiry, 来源钥, 挑战)
    max_entries: usize,
}

/// 单个来源节点钥在缓存中的最大占用槽位：防单钥洪泛挤占他人防重放状态
const MAX_SLOTS_PER_ORIGIN: usize = 4;

impl RelayGuard {
    pub fn new(max_entries: usize) -> Self {
        // 审计 P2 修复：容量 0 会让逐出循环空转死循环，强制下限 1
        Self {
            seen: HashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// 当前某来源在缓存中的占用数——**从 seen 现算**（审计 P0 修复：
    /// 独立计数簿记在 retain 逐出时不同步，曾造成死循环 DoS）
    fn origin_count(&self, origin: &NodeId) -> usize {
        self.seen.values().filter(|(_, o, _)| o == origin).count()
    }

    /// 返回 true = 接受并转发；false = 重放/过期/挑战不符/非法，当场丢弃。
    pub fn accept(
        &mut self,
        ticket: &RelayTicket,
        now_ms: u64,
        expected_challenge: [u8; 32],
    ) -> bool {
        if ticket.verify(now_ms, expected_challenge).is_err() {
            return false;
        }
        let fp = ticket.fingerprint();
        if self.seen.contains_key(&fp) {
            return false; // 重放：同一张票第二次到达
        }
        // 1) 逐出已过期票据
        self.seen.retain(|_, (exp, _, _)| *exp + 2 * 60 * 1000 > now_ms);
        // 2) 红队 red2 修复：逐出旧挑战的死条目（它们对新握手已无保护价值）
        self.seen.retain(|_, (_, _, ch)| *ch == expected_challenge);
        // 3) 单来源限占：洪泛只挤占攻击者自己的槽位（计数现算，循环必有界）
        while self.origin_count(&ticket.origin_node_key) >= MAX_SLOTS_PER_ORIGIN {
            let Some((&fp, _)) = self
                .seen
                .iter()
                .filter(|(_, (_, o, _))| *o == ticket.origin_node_key)
                .min_by_key(|(_, (exp, _, _))| *exp)
                .map(|(fp, v)| (fp, *v))
            else {
                break; // 防御性退出
            };
            self.seen.remove(&fp);
        }
        // 4) 全局容量：先逐旧挑战死条目，仍满则**拒绝新票**（红队 red2 修复：
        //    不逐出当前挑战的活条目——防重放完整性优先于新票可用性；
        //    拒绝是有界可用性损失（≤2h 过期 drained），逐出是无界重放复活）
        while self.seen.len() >= self.max_entries {
            let dead = self
                .seen
                .iter()
                .find(|(_, (_, _, ch))| *ch != expected_challenge)
                .map(|(fp, _)| *fp);
            match dead {
                Some(fp) => {
                    self.seen.remove(&fp);
                }
                None => return false, // 活条目占满：fail-closed，等过期自然排空
            }
        }
        self.seen
            .insert(fp, (ticket.expiry_ms, ticket.origin_node_key, expected_challenge));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn ticket(now: u64, challenge: [u8; 32], nonce: [u8; 16]) -> (Identity, RelayTicket) {
        let origin = Identity::generate().unwrap();
        let dest = Identity::generate().unwrap();
        let mut t = RelayTicket::new(
            &dest.node_id(),
            &origin.node_id(),
            now,
            now + 3_600_000,
            nonce,
            challenge,
        );
        t.sign(&origin).unwrap();
        (origin, t)
    }

    #[test]
    fn sign_verify_and_accept() {
        let (_, t) = ticket(1000, [1; 32], [2; 16]);
        t.verify(1000, [1; 32]).unwrap();
        let mut guard = RelayGuard::new(1000);
        assert!(guard.accept(&t, 1000, [1; 32]));
    }

    #[test]
    fn challenge_binding_rejects_stale_ticket() {
        let (_, t) = ticket(1000, [1; 32], [3; 16]);
        // 旧票（挑战 [1;32]）对新一轮握手的盐 [9;32] 无效——时间加盐的核心
        assert!(t.verify(2000, [9; 32]).is_err());
        let mut guard = RelayGuard::new(1000);
        assert!(!guard.accept(&t, 2000, [9; 32]));
    }

    #[test]
    fn replay_same_ticket_rejected() {
        let (_, t) = ticket(1000, [1; 32], [4; 16]);
        let mut guard = RelayGuard::new(1000);
        assert!(guard.accept(&t, 1000, [1; 32]));
        assert!(!guard.accept(&t, 5000, [1; 32]));
        assert!(!guard.accept(&t, 500_000, [1; 32]));
    }

    #[test]
    fn cache_flood_cannot_evict_live_ticket() {
        // C1/red2 回归：同一挑战纪元内，多来源洪泛垃圾票试图挤掉合法活票的
        // 防重放指纹。修复后策略 = 活条目绝不逐出、满员即 fail-closed 拒新——
        // 重放保护完整性优先于新票可用性。
        let (_, live) = ticket(1000, [1; 32], [4; 16]);
        let dest = Identity::generate().unwrap();
        let mut guard = RelayGuard::new(8);
        assert!(guard.accept(&live, 1000, [1; 32]));
        // 64 个不同来源（各有 4 槽配额）在同一挑战纪元内洪泛
        for i in 0..64u8 {
            let origin = Identity::generate().unwrap();
            let mut junk = RelayTicket::new(
                &dest.node_id(),
                &origin.node_id(),
                1000,
                1000 + 3_600_000,
                [i; 16],
                [1; 32], // 与活票同一挑战：现实中的同一纪元
            );
            junk.sign(&origin).unwrap();
            let _ = guard.accept(&junk, 1000 + i as u64, [1; 32]);
        }
        // 活票仍在有效期内：无论缓存是否被洪泛填满，重放依旧被拒
        assert!(!guard.accept(&live, 1000 + 64, [1; 32]));
    }

    #[test]
    fn new_challenge_requires_new_signature() {
        let (_, mut t) = ticket(1000, [1; 32], [5; 16]);
        t.challenge_hash = [5; 32];
        assert!(t.verify(1000, [5; 32]).is_err(), "改盐必碎签");
        let (_, mut t2) = ticket(1000, [1; 32], [7; 16]);
        t2.nonce = [8; 16];
        assert!(t2.verify(1000, [1; 32]).is_err());
    }

    #[test]
    fn expired_ticket_rejected_with_skew_tolerance() {
        let (_, t) = ticket(1000, [1; 32], [9; 16]);
        let skew = 2 * 60 * 1000;
        assert!(t.verify(1000 + 3_600_000, [1; 32]).is_ok());
        assert!(t.verify(1000 + 3_600_000 + skew, [1; 32]).is_ok(), "偏移容差内");
        assert!(t.verify(1000 + 3_600_000 + skew + 1, [1; 32]).is_err(), "超窗即拒");
    }

    #[test]
    fn ttl_cap_enforced() {
        let origin = Identity::generate().unwrap();
        let dest = Identity::generate().unwrap();
        let mut t = RelayTicket::new(
            &dest.node_id(),
            &origin.node_id(),
            1000,
            1000 + MAX_TICKET_TTL_MS + 1,
            [1; 16],
            [1; 32],
        );
        t.sign(&origin).unwrap();
        assert!(t.verify(1000, [1; 32]).is_err(), "TTL 超 2h 的票无效");
    }

    #[test]
    fn wrong_signer_rejected() {
        let origin = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let dest = Identity::generate().unwrap();
        let mut t = RelayTicket::new(
            &dest.node_id(),
            &origin.node_id(),
            10_000,
            10_000 + 3_600_000,
            [9; 16],
            [1; 32],
        );
        t.sig = mallory.sign(&t.signing_payload()).to_bytes().to_vec();
        assert!(t.verify(10_000, [1; 32]).is_err());
    }
}
