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
