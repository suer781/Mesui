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
