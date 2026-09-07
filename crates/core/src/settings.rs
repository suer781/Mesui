//! 设置持久化：serde + 单个 JSON 文件（不引配置框架）。
//! Kotlin UI 侧的设置中心最终都落到这份模型上。

use crate::adaptive::Thresholds;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeMode {
    FollowSystem,
    Light,
    Dark,
}

/// 通道优先级（拖拽排序后的稳定列表；越靠前越优先）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelKind {
    Bluetooth,
    Lan,
    Direct,
    Relay,
    Tor,
}

impl Default for ChannelPriority {
    fn default() -> Self {
        Self(vec![ChannelKind::Bluetooth, ChannelKind::Lan, ChannelKind::Direct, ChannelKind::Relay, ChannelKind::Tor])
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelPriority(pub Vec<ChannelKind>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProxyMode {
    None,
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyCfg {
    pub mode: ProxyMode,
    pub host: String,
    pub port: u16,
    /// 分通道例外：列在此处的通道不走代理（如蓝牙/局域网免代理）。
    pub bypass: Vec<ChannelKind>,
}

impl Default for ProxyCfg {
    fn default() -> Self {
        Self { mode: ProxyMode::None, host: String::new(), port: 0, bypass: vec![] }
    }
}

/// 人人即节点：贡献范围与条件（默认充电 + 不限量网络才服务）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeServiceCfg {
    pub enabled: bool,
    /// 服务范围（三档）：0=关闭, 1=仅直接联系人,
    /// 2=联系人+二度, 3=任何人（限额人群转发，走转发票+治理器）
    pub scope: u8,
    pub only_when_charging: bool,
    pub only_on_unmetered: bool,
    pub data_cap_mb: Option<u32>,
}

impl Default for NodeServiceCfg {
    fn default() -> Self {
        Self { enabled: true, scope: 1, only_when_charging: true, only_on_unmetered: true, data_cap_mb: Some(200) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppearanceCfg {
    pub theme: ThemeMode,
    pub dynamic_color: bool,
    /// 完整动效 / 减弱动效。
    pub reduced_motion: bool,
}

impl Default for AppearanceCfg {
    fn default() -> Self {
        Self { theme: ThemeMode::FollowSystem, dynamic_color: true, reduced_motion: false }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyCfg {
    pub show_receipts: bool,
    pub show_typing: bool,
    pub link_preview: bool, // 默认关，防 IP 泄漏
    pub screenshot_block: bool,
}

impl Default for PrivacyCfg {
    fn default() -> Self {
        Self { show_receipts: true, show_typing: true, link_preview: false, screenshot_block: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveCfg {
    pub enabled: bool,
    pub thresholds: Thresholds,
}

impl Default for AdaptiveCfg {
    fn default() -> Self {
        Self { enabled: true, thresholds: Thresholds::default() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub appearance: AppearanceCfg,
    pub channel_priority: ChannelPriority,
    pub proxy: ProxyCfg,
    pub node_service: NodeServiceCfg,
    pub adaptive: AdaptiveCfg,
    pub privacy: PrivacyCfg,
    /// 蓝牙稳定性切换判定：心跳达标所需秒数。
    pub bluetooth_switch_seconds: u32,
    /// 严格模式：禁止任何未加密通道外发（默认开）。
    pub strict_crypto: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            appearance: AppearanceCfg::default(),
            channel_priority: ChannelPriority::default(),
            proxy: ProxyCfg::default(),
            node_service: NodeServiceCfg::default(),
            adaptive: AdaptiveCfg::default(),
            privacy: PrivacyCfg::default(),
            bluetooth_switch_seconds: 10,
            strict_crypto: true,
        }
    }
}

impl Settings {
    pub fn save(&self, dir: &Path) -> crate::Result<()> {
        std::fs::create_dir_all(dir).map_err(|e| crate::CoreError::Io(e.to_string()))?;
        let path = Self::file(dir);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| crate::CoreError::Config(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| crate::CoreError::Io(e.to_string()))
    }

    pub fn load_or_default(dir: &Path) -> Self {
        let path = Self::file(dir);
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn file(dir: &Path) -> PathBuf {
        dir.join("settings.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dc-core-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn default_roundtrip_via_json() {
        let dir = tmpdir("roundtrip");
        let s = Settings::default();
        s.save(&dir).unwrap();
        let back = Settings::load_or_default(&dir);
        assert_eq!(s, back);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edited_fields_persist() {
        let dir = tmpdir("edited");
        let mut s = Settings::default();
        s.appearance.theme = ThemeMode::Dark;
        s.appearance.reduced_motion = true;
        s.privacy.link_preview = false;
        s.node_service.enabled = false;
        s.proxy = ProxyCfg { mode: ProxyMode::Socks5, host: "127.0.0.1".into(), port: 9050, bypass: vec![ChannelKind::Bluetooth, ChannelKind::Lan] };
        s.save(&dir).unwrap();
        let back = Settings::load_or_default(&dir);
        assert_eq!(back, s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_falls_back_to_default() {
        let dir = tmpdir("corrupt");
        std::fs::write(Settings::file(&dir), "{not json").unwrap();
        let s = Settings::load_or_default(&dir);
        assert_eq!(s, Settings::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serde_forward_compatible_unknown_fields() {
        // 旧版本读到新版本多出的字段不应崩：serde default + 忽略未知字段
        let dir = tmpdir("forward");
        std::fs::write(Settings::file(&dir), r#"{"appearance":{"theme":"Dark","dynamic_color":true,"reduced_motion":false},"future_field":123}"#).unwrap();
        let s = Settings::load_or_default(&dir);
        assert_eq!(s.appearance.theme, ThemeMode::Dark);
        assert!(s.strict_crypto);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
