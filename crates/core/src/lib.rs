//! dc-core：去中心化聊天 Rust 核心。
//!
//! 分层：身份 / 熵源 → 信封与去重 → 自适应策略 → 加密队列 → 传输（iroh）。
//! 密码学原语全部来自第三方库，本 crate 只做编排与胶水。

pub mod adaptive;
pub mod clock;
pub mod entropy;
pub mod governor;
pub mod envelope;
pub mod identity;
pub mod mailbox;
pub mod nodekey;
pub mod relay;
pub mod retry;
pub mod settings;

#[cfg(feature = "db")]
pub mod queue;

#[cfg(feature = "signal")]
pub mod signal_backend {
    /// 探针：证明 signalapp/libsignal 官方 monorepo git 依赖可构建链接。
    pub fn build_probe() -> &'static str {
        "libsignal-protocol (signalapp/libsignal) built via git dependency"
    }
}

#[cfg(feature = "signal")]
pub mod handshake;

#[cfg(feature = "signal")]
pub mod signal_store;

#[cfg(feature = "ffi")]
pub mod ffi;

// UniFFI 宏要求 UniFfiTag 位于 crate 根，故 setup 必须在 lib.rs 而非子模块
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

/// 统一错误类型。全部经字符串穿透，避免把第三方错误泛型漏进公共 API。
#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("熵源错误: {0}")]
    Entropy(String),
    #[error("密码学错误: {0}")]
    Crypto(String),
    #[error("CBOR 编解码错误: {0}")]
    Cbor(String),
    #[error("数据库错误: {0}")]
    Db(String),
    #[error("IO 错误: {0}")]
    Io(String),
    #[error("配置错误: {0}")]
    Config(String),
}

impl From<ed25519_dalek::SignatureError> for CoreError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        CoreError::Crypto(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
