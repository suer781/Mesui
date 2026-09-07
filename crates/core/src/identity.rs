//! 身份层：Ed25519 长期密钥对。
//!
//! v9 架构复审决议：长期身份密钥**只**用于身份认证与 Signal 加解密，永不充当
//! iroh 节点 ID、永不进入任何发现系统——对外可见的是可轮换的临时节点密钥
//! （见节点服务模块，实现于阶段 5），两者的绑定关系仅存在于联系人 Signal 会话内。

use crate::{CoreError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// 节点 ID = Ed25519 公钥（32 字节）。
pub type NodeId = [u8; 32];

/// 全线统一的 1024 位指纹长度（BLAKE3 XOF 输出 128 字节）。
pub const FINGERPRINT_LEN: usize = 128;

#[derive(Clone)]
pub struct Identity {
    sk: SigningKey,
}

impl Identity {
    /// 由内核 CSPRNG 生成新身份（传感器熵池增强见 `entropy::EntropyHarvester`）。
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| CoreError::Entropy(e.to_string()))?;
        Ok(Self::from_seed(seed))
    }

    /// 确定性重建（测试/恢复流程用；生产恢复路径走 Keystore 导出）。
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(&seed),
        }
    }

    pub fn node_id(&self) -> NodeId {
        *self.sk.verifying_key().as_bytes()
    }

    pub fn public(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sk.sign(msg)
    }
}

/// 严格验证（strongly-typed + 校验规范点，拒绝 malleable 签名）。
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<()> {
    vk.verify_strict(msg, sig).map_err(CoreError::from)
}

/// 1024 位指纹：域分隔的 BLAKE3 XOF。
/// 用途：安全码核对、挑战哈希、熵池搅拌——全线统一这一个函数。
pub fn fingerprint1024(parts: &[&[u8]]) -> [u8; FINGERPRINT_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"dc-fingerprint-v1");
    h.update(&(parts.len() as u32).to_be_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_be_bytes());
        h.update(p);
    }
    let mut out = [0u8; FINGERPRINT_LEN];
    h.finalize_xof().fill(&mut out);
    out
}

/// 身份指纹 = 长期公钥的 1024 位哈希（安全码核对的数据源）。
pub fn identity_fingerprint(node_id: &NodeId) -> [u8; FINGERPRINT_LEN] {
    fingerprint1024(&[b"identity", node_id])
}

/// 指纹格式化：小写十六进制、每 8 字符一组。
pub fn format_fingerprint(fp: &[u8]) -> String {
    let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// 安全码展示：只取前 N 组（默认 4 组 = 16 hex 字符），完整指纹用于核对工具。
pub fn safety_groups(fp: &[u8], groups: usize) -> String {
    format_fingerprint(fp)
        .split(' ')
        .take(groups)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_public_key() {
        let id = Identity::generate().unwrap();
        assert_eq!(id.node_id().len(), 32);
        let id2 = Identity::from_seed(id.clone_seed());
        assert_eq!(id.node_id(), id2.node_id());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::generate().unwrap();
        let msg = b"hello decentralized world";
        let sig = id.sign(msg);
        verify(&id.public(), msg, &sig).unwrap();
        // 篡改必败
        let bad = b"hello decentralized worlD";
        assert!(verify(&id.public(), bad, &sig).is_err());
    }

    #[test]
    fn fingerprint_is_1024bit_and_deterministic() {
        let id = Identity::generate().unwrap();
        let f1 = identity_fingerprint(&id.node_id());
        let f2 = identity_fingerprint(&id.node_id());
        assert_eq!(f1.len(), 128); // 1024 bit
        assert_eq!(f1, f2);
        let other = identity_fingerprint(&Identity::generate().unwrap().node_id());
        assert_ne!(f1, other);
    }

    #[test]
    fn fingerprint_domain_separated() {
        let a = fingerprint1024(&[b"identity", &[1u8; 32]]);
        let b = fingerprint1024(&[&[1u8; 32], b"identity"]);
        assert_ne!(a, b);
    }

    #[test]
    fn format_groups() {
        let fp = [0xabu8; 128];
        let s = format_fingerprint(&fp);
        assert_eq!(s.len(), 128 * 2 + 31); // hex + 31 空格
        assert!(s.starts_with("abababab abababab"));
        let sg = safety_groups(&fp, 4);
        assert_eq!(sg, "abababab abababab abababab abababab");
    }

    #[cfg(test)]
    impl Identity {
        fn clone_seed(&self) -> [u8; 32] {
            self.sk.to_bytes()
        }
    }
}
