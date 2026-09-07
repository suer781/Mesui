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
/// **审计 C4 修订（SP-7 外层化名）**：`sender` 字段语义按路径分流——
/// - 联系人信箱路径：填长期身份公钥（收件方可验）
/// - 人群转发/陌生人路径：**必须填来源轮换节点密钥**（化名），长期身份
///   永不出现在外层——绑定关系只存在于内层密文（Signal 会话）
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
        // 审计 D3：单播与群播互斥——两字段同时存在即畸形信封
        if e.group.is_some() && e.recipient.is_some() {
            return Err(CoreError::Cbor("envelope cannot be both unicast and group".into()));
        }
        if e.ttl_hops == 0 && e.group.is_some() {
            return Err(CoreError::Cbor("group envelope with zero ttl".into()));
        }
        Ok(e)
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
        // 审计 D3：容量 0 会让去重完全失效，强制下限 1
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
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let e = sample();
        let bytes = e.to_cbor().unwrap();
        let back = Envelope::from_cbor(&bytes).unwrap();
        assert_eq!(e, back);
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
