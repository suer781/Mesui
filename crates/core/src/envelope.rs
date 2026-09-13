//! 信封层：CBOR 序列化 + 长度分帧 + 消息 UUID 去重。
//! 信封 body 永远是密文（Signal/OpenMLS 产物），传输层只见信封不见明文。

use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// 消息 UUID（128 位，熵源生成）。
pub type MsgId = [u8; 16];

/// 消息负载种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PayloadKind {
    Text = 1,
    /// 会话管理（Signal 预共享密钥包、会话重置等），对用户不可见。
    SessionMgmt = 2,
    /// 群管理（成员变更、MLS epoch 推进等）。
    GroupMgmt = 3,
    /// 节点间信箱/中继协调。
    NodeCtl = 4,
}

/// 传输信封。字段刻意最小化，减少元数据暴露面。
///
/// `sender` 字段语义按路径分流——
/// - 联系人信箱路径：填长期身份公钥（收件方可验）
/// - 人群转发/陌生人路径：**必须填来源轮换节点密钥**（化名），长期身份
///   永不出现在外层——绑定关系只存在于内层密文（Signal 会话）
///
/// `sig` 字段（A0，2026-09-13 补齐）：可选的发送方 Ed25519 签名，覆盖除
/// `sig` 外的全部字段（见 [`Envelope::signing_payload`]），验证密钥 =
/// `sender` 字段本身。**按路径消费**——
/// - 陌生人中继/群播多跳（SP-7/SP-9）：转发准入凭据，无签名 = 拒转
///   （`crate::relay::verify_forward_credential`；中继解不了内层、也无
///   信箱 MAC 密钥，签名是转发层唯一可验凭据）
/// - 联系人直连/信箱代存：**不消费**该字段——内层 Signal AEAD 与
///   信箱 MAC 已完成认证，签名是冗余防线（历史讨论见 BLE-RELAY-DESIGN 5.2）
///
/// 向后兼容：`skip_serializing_if` 让无签名信封的线上字节与 A0 之前
/// 完全一致（旧端无损解析）；带签名信封多出的字段被旧端 serde 默认
/// 忽略。旧信封（无该字段）经 `#[serde(default)]` 解析为 `None`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub msg_id: MsgId,
    pub sender: crate::identity::NodeId,
    pub recipient: Option<crate::identity::NodeId>,
    /// 群广播时为 Some(群 ID)，此时 recipient 为 None。
    pub group: Option<crate::identity::NodeId>,
    pub kind: PayloadKind,
    /// 密文（可能经 zstd 压缩后加密——压缩永远在加密之前）。
    pub body: Vec<u8>,
    pub sent_at_ms: u64,
    /// 中继跳数预算：蓝牙互助/节点中继每跳 -1，0 则不再转发。
    pub ttl_hops: u8,
    /// 发送方 Ed25519 签名（64 字节，A0）；无签名 = None（旧格式）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Vec<u8>>,
}

impl Envelope {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| CoreError::Cbor(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let e: Envelope = ciborium::de::from_reader(bytes)
            .map_err(|ev| CoreError::Cbor(ev.to_string()))?;
        // 单播与群播互斥——两字段同时存在即畸形信封
        if e.group.is_some() && e.recipient.is_some() {
            return Err(CoreError::Cbor("envelope cannot be both unicast and group".into()));
        }
        if e.ttl_hops == 0 && e.group.is_some() {
            return Err(CoreError::Cbor("group envelope with zero ttl".into()));
        }
        Ok(e)
    }

    /// A0 签名负载：除 `sig` 外全部字段的域分隔规范化串。
    /// 字段绑定方式与 `mailbox::BucketWrite::mac_input` 的信封段一致
    /// （Option 带存在标志，None 与「缺字段」可区分）——签名无法覆盖自身，
    /// 故 `sig` 是唯一不入负载的字段；伪造者改任何其余字段必碎签。
    fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(96 + self.body.len());
        v.extend_from_slice(b"dc-envelope-sig-v1\n");
        v.extend_from_slice(self.msg_id.as_slice());
        v.extend_from_slice(&self.sender);
        match &self.recipient {
            Some(r) => {
                v.push(1);
                v.extend_from_slice(r);
            }
            None => v.push(0),
        }
        match &self.group {
            Some(g) => {
                v.push(1);
                v.extend_from_slice(g);
            }
            None => v.push(0),
        }
        v.push(self.kind as u8);
        v.extend_from_slice(&self.sent_at_ms.to_be_bytes());
        v.push(self.ttl_hops);
        v.extend_from_slice(&self.body);
        v
    }

    /// 发送方签名（A0）：用 `identity` 签署除 `sig` 外的全部字段。
    /// 契约：`identity.node_id()` 必须等于 `sender` 字段——联系人路径传
    /// 长期身份，陌生人路径传轮换节点钥身份（`sender` 即验证公钥）。
    /// 签名者与 sender 不符 = 拒签（冒名在源头 fail-closed）。
    pub fn sign(&mut self, identity: &crate::identity::Identity) -> Result<()> {
        if identity.node_id() != self.sender {
            return Err(CoreError::Crypto("envelope signed by wrong sender key".into()));
        }
        self.sig = Some(identity.sign(&self.signing_payload()).to_bytes().to_vec());
        Ok(())
    }

    /// 信封是否携带发送方签名（降级判定入口）。
    /// 降级行为（A0 评估结论，代码即策略）：
    /// - 陌生人中继/群播多跳：无签名 = 转发层拒绝（见
    ///   `crate::relay::verify_forward_credential`），不静默放行；
    /// - 联系人直连/信箱代存：从不检查本字段，`false` 无任何语义影响。
    pub fn is_sender_signed(&self) -> bool {
        self.sig.is_some()
    }

    /// 验证发送方签名：验证公钥 = `sender` 字段，负载 = 除 `sig` 外全字段。
    /// 错误分类：无签名（"signature missing"）/ 长度非法 / 验签不过——
    /// 调用方按路径处置，转发层三者一律拒绝。
    pub fn verify_sender_sig(&self) -> Result<()> {
        let Some(sig) = &self.sig else {
            return Err(CoreError::Crypto("envelope sender signature missing".into()));
        };
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.sender).map_err(CoreError::from)?;
        let sig = ed25519_dalek::Signature::from_bytes(
            sig.as_slice()
                .try_into()
                .map_err(|_| CoreError::Crypto("signature length must be 64".into()))?,
        );
        crate::identity::verify(&vk, &self.signing_payload(), &sig)
    }
}

/// 长度分帧：4 字节大端长度 + 载荷。蓝牙流/TCP 式通道统一用它。
pub fn frame(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() <= u32::MAX as usize);
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// 单帧上限 4 MiB：超过即判定为损坏/恶意流，立即报错而不是无限缓冲
/// （unframe 的调用方按帧长等待数据，无上限等于给对端一个内存 DoS 开关）。
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// 从缓冲区解出一帧；返回 (载荷, 消耗字节数)。不完整帧返回 None。
pub fn unframe(buf: &[u8]) -> Result<Option<(&[u8], usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(CoreError::Cbor(format!("frame size {len} exceeds {MAX_FRAME_SIZE}")));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some((&buf[4..4 + len], 4 + len)))
}

/// 消息去重集合：FIFO 容量淘汰，通道切换期防重复投递。
#[derive(Debug, Default)]
pub struct Dedup {
    seen: std::collections::HashMap<MsgId, ()>,
    order: std::collections::VecDeque<MsgId>,
    cap: usize,
}

impl Dedup {
    pub fn new(cap: usize) -> Self {
        // 容量 0 会让去重完全失效，强制下限 1
        Self { seen: std::collections::HashMap::new(), order: std::collections::VecDeque::new(), cap: cap.max(1) }
    }

    /// 返回 true = 首次见到；false = 重复。
    pub fn check_and_insert(&mut self, id: MsgId) -> bool {
        if self.seen.insert(id, ()).is_some() {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// 中/重载档批量压缩（zstd）。压缩只在加密之前做，永不加密后压缩。
#[cfg(feature = "compress")]
pub mod compression {
    use crate::{CoreError, Result};

    pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
        zstd::encode_all(data, level).map_err(|e| CoreError::Io(e.to_string()))
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data).map_err(|e| CoreError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn sample() -> Envelope {
        let id = Identity::generate().unwrap();
        Envelope {
            msg_id: [7u8; 16],
            sender: id.node_id(),
            recipient: Some([9u8; 32]),
            group: None,
            kind: PayloadKind::Text,
            body: vec![1, 2, 3, 4, 5],
            sent_at_ms: 1_724_000_000_000,
            ttl_hops: 6,
            sig: None,
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let e = sample();
        let bytes = e.to_cbor().unwrap();
        let back = Envelope::from_cbor(&bytes).unwrap();
        assert_eq!(e, back);
    }

    // ══════════ A0：发送方签名（陌生人中继/群播多跳的转发凭据） ══════════

    /// A0 之前的 9 字段线上格式必须永远可解析（向后兼容）：
    /// 无 sig 字段的旧 CBOR → sig = None。
    #[test]
    fn pre_a0_cbor_without_sig_field_still_parses() {
        #[derive(Serialize, Deserialize)]
        struct LegacyEnvelope {
            msg_id: MsgId,
            sender: crate::identity::NodeId,
            recipient: Option<crate::identity::NodeId>,
            group: Option<crate::identity::NodeId>,
            kind: PayloadKind,
            body: Vec<u8>,
            sent_at_ms: u64,
            ttl_hops: u8,
        }
        let e = sample();
        let legacy = LegacyEnvelope {
            msg_id: e.msg_id,
            sender: e.sender,
            recipient: e.recipient,
            group: e.group,
            kind: e.kind,
            body: e.body.clone(),
            sent_at_ms: e.sent_at_ms,
            ttl_hops: e.ttl_hops,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&legacy, &mut bytes).unwrap();
        let parsed = Envelope::from_cbor(&bytes).unwrap();
        assert!(parsed.sig.is_none(), "旧格式必须解析为无签名");
        assert_eq!(parsed.msg_id, e.msg_id);
        assert_eq!(parsed.sender, e.sender);
        assert_eq!(parsed.body, e.body);
        assert!(!parsed.is_sender_signed());
        assert!(parsed.verify_sender_sig().is_err());
    }

    /// 无签名信封的线上字节与 A0 之前完全一致（skip_serializing_if）；
    /// 带签名信封被「A0 之前结构的解析」正常读取（serde 默认忽略未知字段）
    /// ——旧端升级窗口期双向兼容。
    #[test]
    fn wire_compat_both_directions() {
        #[derive(Serialize, Deserialize)]
        struct LegacyShape {
            msg_id: MsgId,
            sender: crate::identity::NodeId,
            recipient: Option<crate::identity::NodeId>,
            group: Option<crate::identity::NodeId>,
            kind: PayloadKind,
            body: Vec<u8>,
            sent_at_ms: u64,
            ttl_hops: u8,
        }
        // 新端无签名 → 旧端解析：无 sig 字段（字节与旧格式同构）
        let unsigned = sample();
        let bytes = unsigned.to_cbor().unwrap();
        let legacy: LegacyShape = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(legacy.msg_id, unsigned.msg_id);

        // 新端带签名 → 旧端解析：多余字段被忽略，9 字段无损
        let mut signed = sample();
        let signer = Identity::from_seed([3u8; 32]);
        signed.sender = signer.node_id();
        signed.sign(&signer).unwrap();
        let bytes = signed.to_cbor().unwrap();
        let legacy: LegacyShape = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(legacy.msg_id, signed.msg_id);
        assert_eq!(legacy.body, signed.body);
        // 新端自己往返：签名无损、仍可验
        let back = Envelope::from_cbor(&bytes).unwrap();
        assert_eq!(back, signed);
        assert!(back.is_sender_signed());
        back.verify_sender_sig().unwrap();
    }

    /// 签名全字段绑定：改任一入签字段（body/msg_id/ttl/kind/recipient/
    /// sent_at_ms）必碎签；签名者与 sender 不符在 sign 时即拒。
    #[test]
    fn sig_binds_every_field_and_wrong_signer_rejected() {
        let alice = Identity::from_seed([1u8; 32]);
        let mut e = sample();
        e.sender = alice.node_id();
        e.sign(&alice).unwrap();
        e.verify_sender_sig().unwrap();

        let expect_reject = |e: &Envelope| {
            assert!(e.verify_sender_sig().is_err(), "篡改后必须验签失败");
        };
        let mut e1 = e.clone();
        e1.body[0] ^= 1;
        expect_reject(&e1);
        let mut e2 = e.clone();
        e2.msg_id = [8; 16];
        expect_reject(&e2);
        let mut e3 = e.clone();
        e3.ttl_hops -= 1;
        expect_reject(&e3);
        let mut e4 = e.clone();
        e4.kind = PayloadKind::SessionMgmt;
        expect_reject(&e4);
        let mut e5 = e.clone();
        e5.recipient = None;
        expect_reject(&e5);
        let mut e6 = e.clone();
        e6.sent_at_ms += 1;
        expect_reject(&e6);
        let mut e7 = e.clone();
        e7.group = Some([4; 32]);
        expect_reject(&e7);

        // 冒名：Mallory 钥匙 + sender=alice → sign() 拒签（源头 fail-closed）
        let mallory = Identity::from_seed([2u8; 32]);
        let mut forged = sample();
        forged.sender = alice.node_id();
        assert!(forged.sign(&mallory).is_err(), "签名者 ≠ sender 必须拒签");
        assert!(forged.sig.is_none());
        // 即便绕过 sign 直接塞 Mallory 对同负载的签名：验证公钥 = sender，必不过
        forged.sig = Some(mallory.sign(&forged.signing_payload()).to_bytes().to_vec());
        expect_reject(&forged);
    }

    /// 缺失签名的降级行为：错误分类明确（missing ≠ 长度非法 ≠ 验签不过），
    /// 长度非法的 sig 也必须被拒（不得当作无签名放行）。
    #[test]
    fn missing_or_malformed_sig_degradation_is_explicit() {
        let mut e = sample();
        let sender = Identity::from_seed([5u8; 32]);
        e.sender = sender.node_id();
        // 无签名：is_sender_signed=false + 专属错误文案（转发层据此拒转）
        assert!(!e.is_sender_signed());
        let err = e.verify_sender_sig().unwrap_err().to_string();
        assert!(err.contains("missing"), "实际: {err}");
        // 畸形长度：不能被当成「无签名」放过
        e.sig = Some(vec![0u8; 63]);
        assert!(e.verify_sender_sig().is_err());
        e.sig = Some(Vec::new());
        assert!(e.verify_sender_sig().is_err());
        // 正常签名修复一切
        e.sign(&sender).unwrap();
        e.verify_sender_sig().unwrap();
    }

    /// FFI 队列路径信封走 serde_json：带签名往返无损；旧 JSON（无 sig）
    /// 解析为 None（serde default）。
    #[test]
    fn json_roundtrip_preserves_sig_and_old_json_parses() {
        let mut e = sample();
        let signer = Identity::from_seed([9u8; 32]);
        e.sender = signer.node_id();
        let old_json = serde_json::to_string(&e).unwrap();
        assert!(!old_json.contains("sig"), "无签名信封不得出现 sig 字段");
        e.sign(&signer).unwrap();
        let json = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sig, e.sig);
        back.verify_sender_sig().unwrap();
        let old_back: Envelope = serde_json::from_str(&old_json).unwrap();
        assert!(old_back.sig.is_none(), "旧 JSON 必须解析为无签名");
    }

    #[test]
    fn frame_roundtrip_partial_feed() {
        let e = sample();
        let f = frame(&e.to_cbor().unwrap());
        // 半帧喂入必须返回 None（流式解析安全）
        assert!(unframe(&f[..f.len() - 1]).unwrap().is_none());
        assert!(unframe(&f[..3]).unwrap().is_none());
        let (payload, consumed) = unframe(&f).unwrap().unwrap();
        assert_eq!(consumed, f.len());
        assert_eq!(Envelope::from_cbor(payload).unwrap(), e);
    }

    #[test]
    fn frame_back_to_back() {
        let e = sample();
        let f1 = frame(&e.to_cbor().unwrap());
        let f2 = frame(&e.to_cbor().unwrap());
        let mut both = f1.clone();
        both.extend_from_slice(&f2);
        let (p1, c1) = unframe(&both).unwrap().unwrap();
        let (p2, c2) = unframe(&both[c1..]).unwrap().unwrap();
        assert_eq!(Envelope::from_cbor(p1).unwrap(), e);
        assert_eq!(Envelope::from_cbor(p2).unwrap(), e);
        assert_eq!(c1 + c2, both.len());
    }

    #[test]
    fn unframe_rejects_oversized_declared_length() {
        // 声明长度超过上限：即使数据没到也要立刻报错（防内存 DoS）
        let mut head = u32::MAX.to_be_bytes().to_vec();
        head.extend_from_slice(b"junk");
        assert!(unframe(&head).is_err());
        let mut head = (MAX_FRAME_SIZE as u32 + 1).to_be_bytes().to_vec();
        head.extend_from_slice(&[0u8; 16]);
        assert!(unframe(&head).is_err());
    }

    #[test]
    fn dedup_insert_once_and_evict_fifo() {
        let mut d = Dedup::new(3);
        assert!(d.check_and_insert([1; 16]));
        assert!(!d.check_and_insert([1; 16]));
        assert!(d.check_and_insert([2; 16]));
        assert!(d.check_and_insert([3; 16]));
        // 容量 3：插入第 4 条应淘汰最早的 [1;16]
        assert!(d.check_and_insert([4; 16]));
        assert_eq!(d.len(), 3);
        assert!(d.check_and_insert([1; 16]), "被淘汰的旧消息应可重新插入");
    }

    #[cfg(feature = "compress")]
    #[test]
    fn compress_roundtrip_shrinks_repetitive() {
        let data = vec![42u8; 10_000];
        let c = compression::compress(&data, 3).unwrap();
        assert!(c.len() < 100);
        assert_eq!(compression::decompress(&c).unwrap(), data);
    }
}
