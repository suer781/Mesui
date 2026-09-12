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

/// 信箱写桶门禁的 UniFFI 出口（SP-1 第 3/5 条）：
/// Kotlin 侧把线上收到的 BucketWrite 交给核心走完整验收——
/// MAC → ±5min 时间窗 → msg_id 去重 → 按写入方限速（≤30 封/分/对）——
/// 返回 "accepted" 表示可入桶（实际存储由 Kotlin 侧处理）。
///
/// 内部 Mutex 守护可变状态：UniFFI Object 按 &self 分发，
/// Android 多线程并发 submit 在锁上串行化（与 SignalSession 同法）。
/// A2a Verifier P2 修复：持有 InternalClock 实例——now_ms 由 Rust 侧
/// 高水位防回拨钟产生，Kotlin 传入的 raw 时间仅作参考输入。
#[derive(uniffi::Object)]
pub struct MailboxManagerHandle {
    inner: std::sync::Mutex<crate::maildrop::MailboxManager>,
    clock: std::sync::Mutex<crate::clock::InternalClock>,
}

#[uniffi::export]
impl MailboxManagerHandle {
    /// `cap` = msg_id 去重台账软目标容量（实际下限 4096，满则 fail-closed）。
    #[uniffi::constructor]
    pub fn new(cap: u32) -> Self {
        Self {
            inner: std::sync::Mutex::new(crate::maildrop::MailboxManager::new(cap as usize)),
            clock: std::sync::Mutex::new(crate::clock::InternalClock::new()),
        }
    }

    /// 提交一次信箱写入。
    /// - `write_json`：BucketWrite 的 JSON 序列化（UniFFI 不跨复杂结构体；
    ///   字节数组即 JSON 数字数组，PayloadKind 为枚举名如 "Text"）。
    /// - `secret_hex`：该桶该版本的 mailbox secret（64 个 hex 字符）。
    /// - `local_ms`：本地钟读数（Rust 内部钟叠加高水位/校准偏移后使用，
    ///   调用方不可绕过防回拨——A2a Verifier P2 修复）。
    ///
    /// 成功返回 "accepted"；错误文案区分四类门禁判定：
    /// 重放 / 限速 / 验签失败 / 时间窗外（见 maildrop::MailboxError）。
    pub fn submit(
        &self,
        write_json: String,
        secret_hex: String,
        local_ms: u64,
    ) -> Result<String, DcError> {
        let write: crate::mailbox::BucketWrite = serde_json::from_str(&write_json)
            .map_err(|e| DcError::Core { msg: format!("write_json 解析失败: {e}") })?;
        let secret: [u8; 32] = hex_decode_32(&secret_hex).ok_or_else(|| DcError::Core {
            msg: "secret_hex 必须是 64 个 hex 字符（32 字节）".into(),
        })?;
        // P2 修复：高水位防回拨——Kotlin 传入的 local_ms 经 Rust 内部钟处理后使用
        let now_ms = self
            .clock
            .lock()
            .expect("clock mutex poisoned")
            .now(local_ms as i64) as u64;
        self.inner
            .lock()
            .expect("maildrop mutex poisoned")
            .submit_write(&write, &secret, now_ms)
            .map_err(map_sig)?;
        Ok("accepted".to_string())
    }
}

/// 信箱读桶的 UniFFI 出口（SP-1.6 读路径）：
/// 包装桶存储（内存 HashMap 实现；生产由 Kotlin 侧 SQLCipher 按
/// maildrop::BucketStorage 的语义实现后替换），并持有读桶防重放台账
/// （写桶台账在 MailboxManagerHandle，读/写键空间独立、互不串扰）。
///
/// 读请求（MailboxRead）必须经 `seal_bucket_read` 产出——读取 MAC 是
/// keyed-BLAKE3，只能出自核心，Kotlin 侧无法伪造。
#[derive(uniffi::Object)]
pub struct BucketStorageHandle {
    storage: std::sync::Arc<dyn crate::maildrop::BucketStorage>,
    reads: std::sync::Mutex<crate::maildrop::MailboxManager>,
}

#[uniffi::export]
impl BucketStorageHandle {
    /// 内存桶存储（进程退出即丢；测试/演示用）。
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            storage: std::sync::Arc::new(crate::maildrop::InMemoryBucketStorage::default()),
            reads: std::sync::Mutex::new(crate::maildrop::MailboxManager::new(1024)),
        }
    }

    /// 入库一条已验收的写（Kotlin 在 submit() 返回 "accepted" 后调用）。
    /// 返回桶内序号（从 1 起单调递增，即读路径游标的刻度）。
    pub fn store_write(&self, bucket_hex: String, write_json: String) -> Result<u64, DcError> {
        let bucket = hex_decode_32(&bucket_hex).ok_or_else(|| DcError::Core {
            msg: "bucket_hex 必须是 64 个 hex 字符（32 字节）".into(),
        })?;
        let write: crate::mailbox::BucketWrite = serde_json::from_str(&write_json)
            .map_err(|e| DcError::Core { msg: format!("write_json 解析失败: {e}") })?;
        self.storage.store(&bucket, &write).map_err(map_sig)
    }

    /// 桶内消息总数（分页进度提示）。
    pub fn count(&self, bucket_hex: String) -> Result<u64, DcError> {
        let bucket = hex_decode_32(&bucket_hex).ok_or_else(|| DcError::Core {
            msg: "bucket_hex 必须是 64 个 hex 字符（32 字节）".into(),
        })?;
        self.storage.count(&bucket).map_err(map_sig)
    }

    /// 读桶（SP-1.6）：读取 MAC（鉴权）→ nonce 台账（防重放读）→ 游标后取。
    /// - `read_json`：`seal_bucket_read` 产出的 MailboxRead JSON（含
    ///   bucket/serial/nonce/cursor/mac；字节数组为 JSON 数字数组）。
    /// - `cursor`：期望游标——与 read_json 内 MAC 绑定的游标不一致即拒绝
    ///   （fail-closed：游标在 MAC 里，中继/调用方错位必然失配）。
    /// - `now_ms`：本地钟读数（读取无时间窗，仅用于读台账的过期记账）。
    ///
    /// 返回 BucketWrite 的 JSON 数组（按序号升序）；游标后无消息（空桶/
    /// 已读尽）返回 "[]"；鉴权失败/重放/存储故障返回 Err。
    pub fn read_bucket(
        &self,
        read_json: String,
        secret_hex: String,
        cursor: u64,
        now_ms: u64,
    ) -> Result<String, DcError> {
        let read: crate::mailbox::MailboxRead = serde_json::from_str(&read_json)
            .map_err(|e| DcError::Core { msg: format!("read_json 解析失败: {e}") })?;
        let secret = hex_decode_32(&secret_hex).ok_or_else(|| DcError::Core {
            msg: "secret_hex 必须是 64 个 hex 字符（32 字节）".into(),
        })?;
        if read.cursor != cursor {
            return Err(DcError::Core {
                msg: "cursor 与读取请求中 MAC 绑定的游标不一致".into(),
            });
        }
        let writes = self
            .reads
            .lock()
            .expect("read mutex poisoned")
            .read_bucket(&read, &secret, self.storage.as_ref(), now_ms)
            .map_err(map_sig)?;
        serde_json::to_string(&writes)
            .map_err(|e| DcError::Core { msg: format!("writes 序列化失败: {e}") })
    }
}

/// 节点密钥轮换公告分发器的 UniFFI 出口（SP-2.3）：
/// `rotate` 生成并签名新公告（serial 单调递增），`distribute` 把公告经
/// 联系人信箱桶推送（SessionMgmt 信封 → 信箱 MAC 密封 → 入桶，不加密）。
///
/// 长期身份私钥不驻留 FFI 句柄：每次调用传 identity_seed_hex（Kotlin 侧
/// Keystore 解出后传入，与 IrohNode.start 的 seed32 同法）。内部 Mutex 守护
/// 可变状态（serial 计数 + 密钥环），UniFFI Object 按 &self 并发进入时串行化。
#[derive(uniffi::Object)]
pub struct AnnouncementDispatcherHandle {
    inner: std::sync::Mutex<crate::nodekey::AnnouncementDispatcher>,
}

#[uniffi::export]
impl AnnouncementDispatcherHandle {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(crate::nodekey::AnnouncementDispatcher::new()),
        }
    }

    /// 轮换节点密钥：生成 serial+1 的新公告、长期身份签名、入密钥环。
    /// - `identity_seed_hex`：本端长期身份私钥种子（64 个 hex 字符）。
    /// - `new_node_key_hex`：本周期的 iroh 节点公钥（64 个 hex 字符）。
    /// 返回公告 JSON（identity/node_key/serial/not_before_ms/not_after_ms/sig，
    /// 字节数组为 JSON 数字数组）——Kotlin 可持久化/审计后再扇出分发。
    pub fn rotate(
        &self,
        identity_seed_hex: String,
        new_node_key_hex: String,
        now_ms: u64,
    ) -> Result<String, DcError> {
        let seed = hex_arg_32(&identity_seed_hex, "identity_seed_hex")?;
        let node_key = hex_arg_32(&new_node_key_hex, "new_node_key_hex")?;
        let identity = crate::identity::Identity::from_seed(seed);
        let ann = self
            .inner
            .lock()
            .expect("dispatcher mutex poisoned")
            .rotate(&identity, &node_key, now_ms)
            .map_err(map_sig)?;
        serde_json::to_string(&ann)
            .map_err(|e| DcError::Core { msg: format!("公告序列化失败: {e}") })
    }

    /// 当前应拨的节点密钥（hex；该身份无未过期公告时返回 None）。
    pub fn current_key(&self, identity_hex: String, now_ms: u64) -> Result<Option<String>, DcError> {
        let identity = hex_arg_32(&identity_hex, "identity_hex")?;
        Ok(self
            .inner
            .lock()
            .expect("dispatcher mutex poisoned")
            .current_key(&identity, now_ms)
            .map(|k| k.iter().map(|b| format!("{b:02x}")).collect()))
    }

    /// 轮换 + 分发一步完成（SP-2.3 联系人信箱推送路径）：
    /// rotate 产签名公告 → SessionMgmt 信封（公告不加密）→ 按 secret_hex
    /// 密封信箱 MAC → 写入 storage 的 bucket_hex 桶。返回桶内序号（读游标刻度）。
    ///
    /// 多联系人扇出：对每个联系人桶各调一次（每次产新 serial，同一 node_key
    /// 的不同 serial 公告对收方语义等价——`NodeKeyRing` 按最高 serial 取钥）；
    /// 若要求各桶公告完全一致（同 serial），先 `rotate` 再用
    /// `distribute_signed` 扇出。
    pub fn distribute(
        &self,
        identity_seed_hex: String,
        new_node_key_hex: String,
        bucket_hex: String,
        secret_hex: String,
        storage: std::sync::Arc<BucketStorageHandle>,
        now_ms: u64,
    ) -> Result<u64, DcError> {
        let seed = hex_arg_32(&identity_seed_hex, "identity_seed_hex")?;
        let node_key = hex_arg_32(&new_node_key_hex, "new_node_key_hex")?;
        let bucket = hex_arg_32(&bucket_hex, "bucket_hex")?;
        let secret = hex_arg_32(&secret_hex, "secret_hex")?;
        let identity = crate::identity::Identity::from_seed(seed);
        let ann = self
            .inner
            .lock()
            .expect("dispatcher mutex poisoned")
            .rotate(&identity, &node_key, now_ms)
            .map_err(map_sig)?;
        // 公告入桶走与 maildrop::distribute_announcement 同一密封逻辑；
        // BucketStorageHandle 的存储在 Arc 后面（共享），故 seal + store 分步。
        let write = crate::maildrop::seal_announcement_write(&ann, &secret, now_ms)
            .map_err(map_sig)?;
        storage.storage.store(&bucket, &write).map_err(map_sig)
    }

    /// 已有签名公告的扇出（一次轮换、多桶同 serial 分发）：
    /// `ann_json` 为 `rotate()` 的返回值。公告先验签（被篡改即拒绝）再入桶。
    pub fn distribute_signed(
        &self,
        ann_json: String,
        bucket_hex: String,
        secret_hex: String,
        storage: std::sync::Arc<BucketStorageHandle>,
        now_ms: u64,
    ) -> Result<u64, DcError> {
        let ann: crate::nodekey::NodeKeyAnnouncement = serde_json::from_str(&ann_json)
            .map_err(|e| DcError::Core { msg: format!("ann_json 解析失败: {e}") })?;
        let bucket = hex_arg_32(&bucket_hex, "bucket_hex")?;
        let secret = hex_arg_32(&secret_hex, "secret_hex")?;
        let write = crate::maildrop::seal_announcement_write(&ann, &secret, now_ms)
            .map_err(map_sig)?;
        storage.storage.store(&bucket, &write).map_err(map_sig)
    }
}

/// 构造读桶请求（Kotlin 无法自算 keyed-BLAKE3，读取 MAC 必须出自核心）。
/// nonce 由核心熵源随机生成；`serial` = 本次读取使用的 mailbox secret 版本。
/// 返回 MailboxRead 的 JSON，直接作为 BucketStorageHandle.read_bucket 的
/// read_json 入参。
#[uniffi::export]
pub fn seal_bucket_read(
    bucket_hex: String,
    secret_hex: String,
    serial: u32,
    cursor: u64,
) -> Result<String, DcError> {
    let bucket = hex_decode_32(&bucket_hex).ok_or_else(|| DcError::Core {
        msg: "bucket_hex 必须是 64 个 hex 字符（32 字节）".into(),
    })?;
    let secret = hex_decode_32(&secret_hex).ok_or_else(|| DcError::Core {
        msg: "secret_hex 必须是 64 个 hex 字符（32 字节）".into(),
    })?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|e| DcError::Core { msg: format!("读取 nonce 生成失败: {e}") })?;
    let read = crate::mailbox::MailboxRead::seal_read_serial(bucket, &secret, serial, cursor, nonce);
    serde_json::to_string(&read)
        .map_err(|e| DcError::Core { msg: format!("read 序列化失败: {e}") })
}

/// 固定 32 字节 hex 解码（大小写不敏感；长度/字符非法返回 None）。
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *b = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// 32 字节 hex 入参解析（FFI 错误文案带上参数名）。
fn hex_arg_32(s: &str, name: &str) -> Result<[u8; 32], DcError> {
    hex_decode_32(s).ok_or_else(|| DcError::Core {
        msg: format!("{name} 必须是 64 个 hex 字符（32 字节）"),
    })
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

    // maildrop — 信箱写桶门禁（SP-1 限速已接线）
    let md = crate::maildrop::MailboxManager::new(64);
    results.push(format!(
        "maildrop_rate_per_min={} nonce_cache_len={}",
        crate::maildrop::WRITES_PER_MINUTE,
        md.nonce_cache_len(),
    ));

    // nodekey — SP-2.3 公告分发器接线（rotate 即验签入环，链接器保留符号链）
    let mut disp = crate::nodekey::AnnouncementDispatcher::new();
    let disp_id = crate::identity::Identity::generate().unwrap();
    let disp_ann = disp
        .rotate(&disp_id, &crate::identity::Identity::generate().unwrap().node_id(), 1000)
        .expect("dispatcher smoke rotate");
    results.push(format!(
        "nodekey_max_validity={} dispatcher_serial={}",
        crate::nodekey::MAX_VALIDITY_MS,
        disp_ann.serial
    ));

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

/// 信箱写桶 FFI 出口的往返测试：JSON 序列化 → submit 走完整门禁。
///（MailboxManagerHandle 是普通 Rust 结构体，单测直接调用其方法，
/// 与 Kotlin 经 UniFFI 调用走的是同一条路径。）
#[cfg(all(test, feature = "ffi"))]
mod mailbox_ffi_tests {
    use super::*;
    use crate::envelope::{Envelope, PayloadKind};
    use crate::identity::Identity;
    use crate::mailbox::{derive_mailbox_secret, generate_bucket_address, BucketWrite};

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

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn submit_accepts_fresh_write_via_json_and_rejects_replay() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi", &bucket, 1);
        let h = MailboxManagerHandle::new(1024);
        let ts = 1_000_000u64;
        let w = sealed_write(&sender, &secret, 1, ts);
        // JSON 序列化跨 FFI 边界后仍可验：首交通过
        assert_eq!(
            h.submit(serde_json::to_string(&w).unwrap(), hex32(&secret), ts).unwrap(),
            "accepted"
        );
        // 同一写再交一次 = 重放（msg_id 台账命中），错误文案可区分
        let err = h
            .submit(serde_json::to_string(&w).unwrap(), hex32(&secret), ts)
            .unwrap_err();
        assert!(err.to_string().contains("重放"), "实际: {err}");
    }

    #[test]
    fn submit_rejects_malformed_json_and_hex() {
        let h = MailboxManagerHandle::new(1024);
        let hex_ok = "ab".repeat(32);
        // 非 JSON / 缺字段的 JSON
        assert!(h.submit("not json".into(), hex_ok.clone(), 0).is_err());
        assert!(h.submit("{}".into(), hex_ok.clone(), 0).is_err());
        // hex 长度不足 / 字符非法
        assert!(h.submit("{}".into(), "ab".repeat(31), 0).is_err());
        assert!(h.submit("{}".into(), "zz".repeat(32), 0).is_err());
    }

    #[test]
    fn submit_surfaces_rate_limit_error_text() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi", &bucket, 1);
        let h = MailboxManagerHandle::new(1024);
        let ts = 2_000_000u64;
        // 打满 30 封后第 31 封在 FFI 层得到限速文案
        for i in 0..crate::maildrop::WRITES_PER_MINUTE {
            let w = sealed_write(&sender, &secret, (i as u8) + 1, ts);
            h.submit(serde_json::to_string(&w).unwrap(), hex32(&secret), ts)
                .unwrap();
        }
        let err = h
            .submit(
                serde_json::to_string(&sealed_write(&sender, &secret, 99, ts)).unwrap(),
                hex32(&secret),
                ts,
            )
            .unwrap_err();
        assert!(err.to_string().contains("限速"), "实际: {err}");
    }

    // ══════════ 读桶 FFI（SP-1.6） ══════════

    #[test]
    fn read_bucket_via_ffi_returns_writes_after_cursor() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi-read", &bucket, 1);
        let ts = 3_000_000u64;
        let gate = MailboxManagerHandle::new(1024);
        let st = BucketStorageHandle::new();
        // 生产顺序：写门禁 submit → 入库 store_write
        for i in 1..=3u8 {
            let w = sealed_write(&sender, &secret, i, ts);
            assert_eq!(
                gate.submit(serde_json::to_string(&w).unwrap(), hex32(&secret), ts).unwrap(),
                "accepted"
            );
            assert_eq!(
                st.store_write(hex32(&bucket), serde_json::to_string(&w).unwrap()).unwrap(),
                i as u64
            );
        }
        assert_eq!(st.count(hex32(&bucket)).unwrap(), 3);
        // 封读请求（MAC 出自核心）→ 游标 0 读全部
        let read_json = seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 0).unwrap();
        let out = st.read_bucket(read_json, hex32(&secret), 0, ts).unwrap();
        let all: Vec<BucketWrite> = serde_json::from_str(&out).unwrap();
        assert_eq!(all.len(), 3);
        // 游标 2 → 只剩第 3 条
        let read_json = seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 2).unwrap();
        let out = st.read_bucket(read_json, hex32(&secret), 2, ts).unwrap();
        let tail: Vec<BucketWrite> = serde_json::from_str(&out).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].envelope.msg_id, [3; 16]);
        // 读尽 → "[]"（空数组而非错误）
        let read_json = seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 3).unwrap();
        assert_eq!(st.read_bucket(read_json, hex32(&secret), 3, ts).unwrap(), "[]");
        // 空桶 → "[]"
        let empty_bucket = generate_bucket_address().unwrap();
        let read_json = seal_bucket_read(hex32(&empty_bucket), hex32(&secret), 1, 0).unwrap();
        assert_eq!(st.read_bucket(read_json, hex32(&secret), 0, ts).unwrap(), "[]");
    }

    #[test]
    fn read_bucket_via_ffi_rejects_replay_and_cursor_mismatch() {
        let sender = Identity::generate().unwrap();
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi-read", &bucket, 1);
        let ts = 3_000_000u64;
        let st = BucketStorageHandle::new();
        let w = sealed_write(&sender, &secret, 1, ts);
        st.store_write(hex32(&bucket), serde_json::to_string(&w).unwrap()).unwrap();
        // 未授权 secret：攻击者用自选钥匙封读请求，桶主用自己的 secret 验 → 失配
        let wrong = derive_mailbox_secret(b"attacker", &bucket, 1);
        let forged = seal_bucket_read(hex32(&bucket), hex32(&wrong), 1, 0).unwrap();
        assert!(st.read_bucket(forged, hex32(&secret), 0, ts).is_err());
        // 游标错位：read_json 封的是 0，实参传 2 → fail-closed
        let read_json = seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 0).unwrap();
        assert!(st.read_bucket(read_json.clone(), hex32(&secret), 2, ts).is_err());
        // 首读放行
        st.read_bucket(read_json.clone(), hex32(&secret), 0, ts).unwrap();
        // 同一 read_json 重放：读台账命中，错误文案可区分
        let err = st.read_bucket(read_json, hex32(&secret), 0, ts).unwrap_err();
        assert!(err.to_string().contains("重放"), "实际: {err}");
        // 坏 JSON / 坏 hex
        assert!(st.read_bucket("not json".into(), hex32(&secret), 0, ts).is_err());
        assert!(seal_bucket_read("zz".repeat(32), hex32(&secret), 1, 0).is_err());
    }
}

/// SP-2.3 公告分发 FFI 的往返测试：直接调用 Handle 方法（与 Kotlin 经
/// UniFFI 调用走同一签名路径）。
#[cfg(all(test, feature = "ffi"))]
mod announcement_ffi_tests {
    use super::*;
    use crate::envelope::PayloadKind;
    use crate::identity::Identity;
    use crate::mailbox::{derive_mailbox_secret, generate_bucket_address};
    use crate::nodekey::{NodeKeyAnnouncement, NodeKeyRing, DEFAULT_OVERLAP_MS};
    use std::sync::Arc;

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fresh_seed() -> ([u8; 32], Identity) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        (seed, Identity::from_seed(seed))
    }

    #[test]
    fn dispatcher_ffi_rotate_distribute_current_end_to_end() {
        let t0 = 10_000_000u64;
        let (seed, alice) = fresh_seed();
        let h = AnnouncementDispatcherHandle::new();
        let st = Arc::new(BucketStorageHandle::new());

        // rotate：返回公告 JSON 可解、serial=1、sig 已填且可验
        let k1 = Identity::generate().unwrap().node_id();
        let ann_json = h.rotate(hex32(&seed), hex32(&k1), t0).unwrap();
        let ann: NodeKeyAnnouncement = serde_json::from_str(&ann_json).unwrap();
        assert_eq!(ann.serial, 1);
        assert_eq!(ann.identity, alice.node_id());
        ann.verify().unwrap();

        // distribute：rotate+写桶一步完成 → 桶内序号 1
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi-sp2", &bucket, 1);
        let seq = h
            .distribute(
                hex32(&seed),
                hex32(&k1),
                hex32(&bucket),
                hex32(&secret),
                st.clone(),
                t0,
            )
            .unwrap();
        assert_eq!(seq, 1);

        // 收方：seal_bucket_read 读回 → SessionMgmt 信封 → CBOR → upsert → current 新钥
        let read_json = seal_bucket_read(hex32(&bucket), hex32(&secret), 1, 0).unwrap();
        let out = st.read_bucket(read_json, hex32(&secret), 0, t0).unwrap();
        let writes: Vec<crate::mailbox::BucketWrite> = serde_json::from_str(&out).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].envelope.kind, PayloadKind::SessionMgmt);
        writes[0].verify(&secret, t0).unwrap();
        let got = NodeKeyAnnouncement::from_cbor(&writes[0].envelope.body).unwrap();
        let mut ring = NodeKeyRing::new();
        ring.upsert(&got, t0).unwrap();
        assert_eq!(ring.current(&alice.node_id(), t0), Some(&k1));
        // FFI current_key 视图同步
        assert_eq!(
            h.current_key(hex32(&alice.node_id()), t0).unwrap(),
            Some(hex32(&k1))
        );
        // 未知身份 → None
        assert_eq!(h.current_key(hex32(&[0u8; 32]), t0).unwrap(), None);
    }

    #[test]
    fn dispatcher_ffi_distribute_signed_fans_out_same_serial() {
        // rotate 一次 → distribute_signed 把同一公告（同 serial）扇出到两个联系人桶
        let t0 = 10_000_000u64;
        let (seed, alice) = fresh_seed();
        let k1 = Identity::generate().unwrap().node_id();
        let h = AnnouncementDispatcherHandle::new();
        let st = Arc::new(BucketStorageHandle::new());
        let ann_json = h.rotate(hex32(&seed), hex32(&k1), t0).unwrap();

        let b1 = generate_bucket_address().unwrap();
        let b2 = generate_bucket_address().unwrap();
        let s1 = derive_mailbox_secret(b"ffi-fan", &b1, 1);
        let s2 = derive_mailbox_secret(b"ffi-fan", &b2, 1);
        assert_eq!(
            h.distribute_signed(ann_json.clone(), hex32(&b1), hex32(&s1), st.clone(), t0)
                .unwrap(),
            1
        );
        assert_eq!(
            h.distribute_signed(ann_json, hex32(&b2), hex32(&s2), st.clone(), t0)
                .unwrap(),
            1
        );
        // 两桶读回的公告完全一致（一次轮换、多桶分发）
        for (b, s) in [(&b1, &s1), (&b2, &s2)] {
            let read_json = seal_bucket_read(hex32(b), hex32(s), 1, 0).unwrap();
            let out = st.read_bucket(read_json, hex32(s), 0, t0).unwrap();
            let writes: Vec<crate::mailbox::BucketWrite> = serde_json::from_str(&out).unwrap();
            assert_eq!(writes.len(), 1);
            let got = NodeKeyAnnouncement::from_cbor(&writes[0].envelope.body).unwrap();
            assert_eq!(got.serial, 1);
            assert_eq!(got.node_key, k1);
            let mut ring = NodeKeyRing::new();
            ring.upsert(&got, t0).unwrap();
            assert_eq!(ring.current(&alice.node_id(), t0), Some(&k1));
        }
    }

    #[test]
    fn dispatcher_ffi_rejects_bad_hex_and_forged_announcement() {
        let h = AnnouncementDispatcherHandle::new();
        let st = Arc::new(BucketStorageHandle::new());
        let t0 = 10_000_000u64;
        // 坏 hex：seed / node key 各自被拒（长度不足、字符非法）
        assert!(h.rotate("zz".repeat(32), hex32(&[0; 32]), t0).is_err());
        assert!(h.rotate(hex32(&[0; 32]), "ab".repeat(31), t0).is_err());

        // 伪造公告：合法 JSON 但签名与内容不符 → distribute_signed 验签拒绝
        let (seed, alice) = fresh_seed();
        let k1 = Identity::generate().unwrap().node_id();
        let mut ann =
            NodeKeyAnnouncement::new(&alice.node_id(), &k1, 1, t0, DEFAULT_OVERLAP_MS);
        ann.sign(&alice).unwrap();
        ann.node_key = [9; 32]; // 签名后篡改
        let bucket = generate_bucket_address().unwrap();
        let secret = derive_mailbox_secret(b"ffi-forge", &bucket, 1);
        assert!(h
            .distribute_signed(
                serde_json::to_string(&ann).unwrap(),
                hex32(&bucket),
                hex32(&secret),
                st,
                t0
            )
            .is_err());
    }
}
