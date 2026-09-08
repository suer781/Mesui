//! UniFFI 桥接骨架：Kotlin 侧可调用的核心入口。
//! Android 集成阶段在此追加完整 API 面（会话、队列、通道编排的事件回调）。

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(uniffi::Object)]
pub struct CoreInfo;

#[uniffi::export]
impl CoreInfo {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn version(&self) -> String {
        APP_VERSION.to_string()
    }

    pub fn license(&self) -> String {
        "AGPL-3.0-or-later".to_string()
    }
}

/// 阻止 linker --gc-sections 回收核心模块。
/// 每个 Rust 模块的公开函数被调用一次，linker 即保留该模块的全部依赖链。
/// 没有这个函数，ffi.rs 的 CoreInfo 不引用任何核心类型，
/// linker 会把全部 crate 代码当死代码回收，产出空壳 .so。
#[uniffi::export]
pub fn smoke_test_all_modules() -> String {
    let mut results = Vec::new();

    // adaptive
    let mut pe = crate::adaptive::PolicyEngine::new(Default::default());
    let tier = pe.observe(crate::adaptive::Metrics { group_size: 1, msg_rate: 0.0 });
    results.push(format!("adaptive={:?}", tier));

    // entropy
    let mut h = crate::entropy::EntropyHarvester::new().unwrap();
    let mut token = [0u8; 8];
    h.draw(&mut token).unwrap();
    results.push(format!("entropy={:02x}", token[0]));

    // envelope
    let max_frame = crate::envelope::MAX_FRAME_SIZE;
    results.push(format!("envelope_max_frame={}", max_frame));

    // identity
    let id = crate::identity::Identity::generate().unwrap();
    let fp = crate::identity::identity_fingerprint(&id.node_id());
    results.push(format!("identity_fp_len={}", fp.len()));

    // mailbox
    results.push(format!("mailbox_replay_window={}", crate::mailbox::REPLAY_WINDOW_MS));

    // nodekey
    results.push(format!("nodekey_max_validity={}", crate::nodekey::MAX_VALIDITY_MS));

    // relay
    results.push(format!("relay_ticket_ttl={}", crate::relay::MAX_TICKET_TTL_MS));

    // retry
    results.push(format!("retry_max_attempts={}", crate::retry::RetryPolicy::default().max_attempts));

    // clock
    results.push(format!("clock_net_cap={}", crate::clock::NETWORK_ADOPTION_CAP_MS));

    // settings
    let s = crate::settings::Settings::default();
    results.push(format!("settings_strict={}", s.strict_crypto));

    // governor
    let mut g = crate::governor::RelayGovernor::new(120);
    results.push(format!("governor_share={:.2}", g.share()));

    // queue — 只在 db feature 启用时编译
    #[cfg(feature = "db")]
    {
        let db = crate::queue::Db::open(std::path::Path::new(":memory:"), Some("smoke")).unwrap();
        let (pending, dead, seen) = db.stats().unwrap();
        results.push(format!("queue_pending={} dead={} seen={}", pending, dead, seen));
    }

    format!("smoke_test_all_modules: [{}]", results.join(", "))
}

/// 跨 FFI 的统一错误：Core 为一般失败；RemoteIdentityChanged 单独成类——
/// TOFU 拒绝是「对方换长期钥匙」的安全信号，UI 须区别处理。
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DcError {
    #[error("{msg}")]
    Core { msg: String },
    #[error("对方身份已变更（{name} 已绑定不同的长期身份钥），需重新带外验证")]
    RemoteIdentityChanged { name: String },
}

fn map_err(e: crate::CoreError) -> DcError {
    match e {
        crate::CoreError::IdentityChanged(name) => DcError::RemoteIdentityChanged { name },
        other => DcError::Core { msg: other.to_string() },
    }
}

fn map_sig<E: std::fmt::Display>(e: E) -> DcError {
    DcError::Core { msg: e.to_string() }
}

/// Signal 握手的 UniFFI 导出层：让 Kotlin 侧能调到手势核心（handshake.rs）。
/// FFI 面只暴露可跨边界的类型（String / Vec<u8> / bool / Record），
/// libsignal 类型一律转成字节，Device 用 Mutex 内部可变以满足 UniFFI Object 的 &self 契约。
#[cfg(feature = "signal")]
mod signal_ffi {
    use super::{DcError, map_err, map_sig};
    use crate::handshake::{self, Device};
    use libsignal_protocol::{DeviceId, IdentityKey, PreKeySignalMessage, ProtocolAddress};
    use std::sync::Mutex;

    fn addr(name: &str) -> Result<ProtocolAddress, DcError> {
        let device = DeviceId::new(1).map_err(|e| DcError::Core { msg: format!("{e:?}") })?;
        Ok(ProtocolAddress::new(name.to_owned(), device))
    }

    fn identity_from(bytes: &[u8]) -> Result<IdentityKey, DcError> {
        IdentityKey::decode(bytes).map_err(map_sig)
    }

    /// 一条线上消息（类型字节 + 密文），对应 Rust 侧 encrypt/decrypt 的 (u8, Vec<u8>)。
    #[derive(uniffi::Record)]
    pub struct WireMessage {
        pub msg_type: u8,
        pub ciphertext: Vec<u8>,
    }

    /// SAS 比对码：完整显示串 + 6 位短码。
    #[derive(uniffi::Record)]
    pub struct SasCode {
        pub full: String,
        pub six: String,
    }

    /// Kotlin 侧握手会话句柄。
    #[derive(uniffi::Object)]
    pub struct SignalSession {
        inner: Mutex<Device>,
    }

    #[uniffi::export]
    impl SignalSession {
        /// 生成新设备会话（内存 store，进程退出即丢）。name 为本设备地址标识。
        #[uniffi::constructor]
        pub fn generate(name: String) -> Result<Self, DcError> {
            Ok(Self { inner: Mutex::new(Device::generate(&name).map_err(map_err)?) })
        }

        /// 持久化会话：SQLCipher 加密库，身份/会话/TOFU pin 重启不丢。
        /// path 为库文件路径，key 为 SQLCipher 密钥（无引号字符，hex）。
        /// 首次打开生成长期身份并落盘，之后重开沿用。
        #[uniffi::constructor]
        pub fn open(path: String, key: String, name: String) -> Result<Self, DcError> {
            Ok(Self {
                inner: Mutex::new(
                    Device::open(
                        std::path::Path::new(&path),
                        Some(key.as_str()),
                        &name,
                    )
                    .map_err(map_err)?,
                ),
            })
        }

        /// 本设备长期身份公钥（序列化字节，供对端 SAS/TOFU）。
        pub fn identity_key(&self) -> Result<Vec<u8>, DcError> {
            let d = self.inner.lock().unwrap();
            Ok(d.identity_key().map_err(map_err)?.serialize().to_vec())
        }

        /// 被扫方：产出可编入 QR / 走蓝牙的 PreKeyBundle 字节。
        pub fn prekey_bundle_wire(&self) -> Result<Vec<u8>, DcError> {
            let mut d = self.inner.lock().unwrap();
            let bundle = d.prekey_bundle().map_err(map_err)?;
            handshake::bundle_to_wire(&bundle).map_err(map_err)
        }

        /// 扫码方：用收到的 bundle 字节跑 PQXDH 建立会话。
        pub fn process_bundle(&self, remote_name: String, wire: Vec<u8>) -> Result<(), DcError> {
            let mut d = self.inner.lock().unwrap();
            let bundle = handshake::bundle_from_wire(&wire).map_err(map_err)?;
            d.process_bundle(&addr(&remote_name)?, &bundle).map_err(map_err)
        }

        /// 加密发一条消息（Double Ratchet 自动换钥）。
        pub fn encrypt(&self, remote_name: String, plaintext: Vec<u8>) -> Result<WireMessage, DcError> {
            let mut d = self.inner.lock().unwrap();
            let (t, ct) = d.encrypt(&addr(&remote_name)?, &plaintext).map_err(map_err)?;
            Ok(WireMessage { msg_type: t, ciphertext: ct })
        }

        /// 解密收一条消息。
        pub fn decrypt(&self, remote_name: String, msg: WireMessage) -> Result<Vec<u8>, DcError> {
            let mut d = self.inner.lock().unwrap();
            d.decrypt(&addr(&remote_name)?, msg.msg_type, &msg.ciphertext).map_err(map_err)
        }

        /// 计算 SAS：绑定双方长期身份公钥，两端得到同一串。remote_identity 为对方身份公钥字节。
        pub fn sas_with(
            &self,
            local_name: String,
            remote_name: String,
            remote_identity: Vec<u8>,
        ) -> Result<SasCode, DcError> {
            let d = self.inner.lock().unwrap();
            let local_key = d.identity_key().map_err(map_err)?;
            let remote_key = identity_from(&remote_identity)?;
            let (full, six) = handshake::sas_code(
                local_name.as_bytes(),
                &local_key,
                remote_name.as_bytes(),
                &remote_key,
            )
            .map_err(map_err)?;
            Ok(SasCode { full, six })
        }

        /// TOFU：带外(SAS)比对通过后 pin 对方长期身份公钥。
        pub fn pin_identity(&self, remote_name: String, remote_identity: Vec<u8>) -> Result<(), DcError> {
            let mut d = self.inner.lock().unwrap();
            let key = identity_from(&remote_identity)?;
            d.pin_identity(&addr(&remote_name)?, &key).map_err(map_err)?;
            Ok(())
        }

        /// 校验对方长期身份公钥是否已被信任（重连免扫码的判定）。
        pub fn is_trusted(&self, remote_name: String, remote_identity: Vec<u8>) -> Result<bool, DcError> {
            let d = self.inner.lock().unwrap();
            let key = identity_from(&remote_identity)?;
            d.is_trusted(&addr(&remote_name)?, &key).map_err(map_err)
        }
    }

    /// 首条握手消息的带外 token-MAC（keyed-BLAKE3）。bucket 必须 32 字节。
    #[uniffi::export]
    pub fn first_message_mac(token: Vec<u8>, bucket: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, DcError> {
        let b: [u8; 32] = bucket
            .as_slice()
            .try_into()
            .map_err(|_| DcError::Core { msg: "bucket must be 32 bytes".into() })?;
        Ok(handshake::first_message_mac(&token, &b, &ciphertext).to_vec())
    }

    /// 校验首条握手消息的 token-MAC；返回是否通过。
    #[uniffi::export]
    pub fn verify_first_message_mac(
        token: Vec<u8>,
        bucket: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<bool, DcError> {
        let b: [u8; 32] = bucket
            .as_slice()
            .try_into()
            .map_err(|_| DcError::Core { msg: "bucket must be 32 bytes".into() })?;
        let m: [u8; 32] = mac
            .as_slice()
            .try_into()
            .map_err(|_| DcError::Core { msg: "mac must be 32 bytes".into() })?;
        Ok(handshake::verify_first_message_mac(&token, &b, &ciphertext, &m).is_ok())
    }

    /// 从首条 PreKeySignalMessage 取发送方长期身份公钥（出示侧收到
    /// 扫码方首条消息后计算 SAS 需要；libsignal 消息自带身份键并已随
    /// bundle 签名链验证，不再另行信任来源）。
    #[uniffi::export]
    pub fn prekey_sender_identity(ciphertext: Vec<u8>) -> Result<Vec<u8>, DcError> {
        let msg = PreKeySignalMessage::try_from(ciphertext.as_slice()).map_err(map_sig)?;
        Ok(msg.identity_key().serialize().to_vec())
    }

    /// 联系人（Kotlin 侧 Record；字段含义见 contacts::ContactInfo）。
    #[derive(uniffi::Record)]
    pub struct Contact {
        pub name: String,
        pub identity: Vec<u8>,
        pub bucket: Vec<u8>,
        pub verified: bool,
        pub note: String,
        pub added_ms: i64,
        pub link_secret: Vec<u8>,
        pub node_id: String,
        pub node_naddr: String,
    }

    /// 一条聊天记录。
    #[derive(uniffi::Record)]
    pub struct ChatMessage {
        pub peer: String,
        pub outgoing: bool,
        pub text: String,
        pub ts_ms: i64,
    }

    /// 联系人 + 聊天记录的 Kotlin 句柄（SQLCipher 落盘）。
    #[derive(uniffi::Object)]
    pub struct ContactStore {
        inner: crate::contacts::ContactStore,
    }

    // ContactStore 内部 Mutex 仅守护 &self 方法；uniffi::Object 按 &self 分发
    #[uniffi::export]
    impl ContactStore {
        /// 打开（或创建）联系人库。path/key 与 SignalSession.open 同库同 key
        /// （不同表；双连接靠 busy_timeout 串行化）。
        #[uniffi::constructor]
        pub fn open(path: String, key: String) -> Result<Self, DcError> {
            Ok(Self {
                inner: crate::contacts::ContactStore::open(
                    std::path::Path::new(&path),
                    Some(key.as_str()),
                )
                .map_err(map_err)?,
            })
        }

        pub fn upsert_contact(
            &self,
            name: String,
            identity: Vec<u8>,
            bucket: Vec<u8>,
            verified: bool,
            note: String,
            link_secret: Vec<u8>,
            node_id: String,
            node_naddr: String,
        ) -> Result<(), DcError> {
            self.inner
                .upsert(&name, &identity, &bucket, verified, &note, &link_secret, &node_id, &node_naddr)
                .map_err(map_err)
        }

        pub fn list_contacts(&self) -> Result<Vec<Contact>, DcError> {
            let list = self.inner.list().map_err(map_err)?;
            Ok(list
                .into_iter()
                .map(|c| Contact {
                    name: c.name,
                    identity: c.identity,
                    bucket: c.bucket,
                    verified: c.verified,
                    note: c.note,
                    added_ms: c.added_ms,
                    link_secret: c.link_secret,
                    node_id: c.node_id,
                    node_naddr: c.node_naddr,
                })
                .collect())
        }

        pub fn set_verified(&self, name: String, verified: bool) -> Result<(), DcError> {
            self.inner.set_verified(&name, verified).map_err(map_err)
        }

        pub fn delete_contact(&self, name: String) -> Result<(), DcError> {
            self.inner.delete(&name).map_err(map_err)
        }

        pub fn append_message(&self, peer: String, outgoing: bool, text: String) -> Result<(), DcError> {
            self.inner.append_message(&peer, outgoing, &text).map_err(map_err)
        }

        /// 每个 peer 最新一条（会话列表用），时间降序。
        pub fn last_messages(&self) -> Result<Vec<ChatMessage>, DcError> {
            let list = self.inner.last_messages().map_err(map_err)?;
            Ok(list
                .into_iter()
                .map(|m| ChatMessage {
                    peer: m.peer,
                    outgoing: m.outgoing,
                    text: m.text,
                    ts_ms: m.ts_ms,
                })
                .collect())
        }

        /// 最近 limit 条，时间升序。
        pub fn messages(&self, peer: String, limit: i32) -> Result<Vec<ChatMessage>, DcError> {
            let list = self.inner.messages(&peer, limit).map_err(map_err)?;
            Ok(list
                .into_iter()
                .map(|m| ChatMessage {
                    peer: m.peer,
                    outgoing: m.outgoing,
                    text: m.text,
                    ts_ms: m.ts_ms,
                })
                .collect())
        }
    }
}

/// iroh 远程节点 FFI（阶段 5）：常驻 QUIC 端点，联系人间跨网络收发。
/// v9 红线：无 n0 依赖，地址来自 QR 携带的 dc://node 快照。
/// 根级模块：不依赖 signal feature；回调 trait 需先于引用它的 Object 注册。
#[cfg(feature = "iroh-net")]
mod node_ffi {
    use super::{DcError, map_err};
    use std::sync::Arc;

    /// Kotlin 实现的节点回调（UniFFI callback interface，Rust 任意线程回调）。
    #[uniffi::export(callback_interface)]
    pub trait NodeCallback: Send + Sync {
        /// 收到一条消息（from 为对端节点 id hex；payload = msg_type+密文）。
        fn on_message(&self, from_node_id_hex: String, payload: Vec<u8>);
        /// 端点就绪：本端节点 id + 地址快照（编 QR 用）。
        fn on_ready(&self, node_id_hex: String, naddr: String);
    }

    struct SinkAdapter(Box<dyn NodeCallback>);

    impl crate::node::NodeSink for SinkAdapter {
        fn on_message(&self, from_node_id_hex: String, payload: Vec<u8>) {
            self.0.on_message(from_node_id_hex, payload);
        }
        fn on_ready(&self, node_id_hex: String, naddr: String) {
            self.0.on_ready(node_id_hex, naddr);
        }
    }

    /// 常驻节点句柄。seed32 由 Kotlin 首次随机生成并加密落盘，重启沿用
    /// （节点 id 稳定 → 联系人侧快照长期有效）。
    #[derive(uniffi::Object)]
    pub struct IrohNode {
        inner: crate::node::Node,
    }

    #[uniffi::export]
    impl IrohNode {
        #[uniffi::constructor]
        pub fn start(
            relay_url: String,
            seed32: Vec<u8>,
            callback: Box<dyn NodeCallback>,
        ) -> Result<Self, DcError> {
            let seed: [u8; 32] = seed32
                .as_slice()
                .try_into()
                .map_err(|_| DcError::Core { msg: "seed must be 32 bytes".into() })?;
            Ok(Self {
                inner: crate::node::Node::start(&relay_url, &seed, Arc::new(SinkAdapter(callback)))
                    .map_err(map_err)?,
            })
        }

        pub fn node_id_hex(&self) -> String {
            self.inner.node_id_hex()
        }

        pub fn export_naddr(&self) -> String {
            self.inner.export_naddr()
        }

        /// 按快照发送（阻塞至对端应用层确认；调用方放 IO 线程）。
        pub fn send(&self, naddr: String, payload: Vec<u8>, timeout_ms: u32) -> Result<(), DcError> {
            self.inner.send(&naddr, &payload, timeout_ms as u64).map_err(map_err)
        }

        pub fn stop(&self) {
            self.inner.stop();
        }
    }

    /// 快照 → 节点 id hex（配对落库时从对方快照提取）。
    #[uniffi::export]
    pub fn node_id_from_naddr(naddr: String) -> Result<String, DcError> {
        crate::node::node_id_of_naddr(&naddr).map_err(map_err)
    }
}
