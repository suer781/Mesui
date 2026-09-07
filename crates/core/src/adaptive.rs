//! 自适应负载引擎：按实时指标自动切换档位（轻载/中载/重载）。
//! 切换发生在策略层（算法/拓扑），不在语言层——切换零丢失由信封 UUID 去重保证。
//!
//! 边界：档位**只影响传输策略**（扇出拓扑/批量/压缩/心跳），
//! 不切换加密协议——群加密协议由建群时定死（隐私群 pairwise / 效率群 OpenMLS），
//! 因为 pairwise→MLS 是需全群 rekey 的协议迁移，不能当状态机换挡。

use serde::{Deserialize, Serialize};

pub const DEFAULT_GROUP_MEDIUM: u32 = 50;
pub const DEFAULT_RATE_MEDIUM: f32 = 20.0;
pub const DEFAULT_DEMOTE_SAMPLES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    Light,
    Medium,
    Heavy,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Light => "轻载",
            Tier::Medium => "中载",
            Tier::Heavy => "重载",
        }
    }
}

/// 阈值配置（设置中心「自适应策略」页可调，全部可 serde 持久化）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    pub group_medium: u32,
    pub rate_medium: f32,
    /// 持续低于下阈值多少个采样周期才降档（防抖）。
    pub demote_samples: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            group_medium: DEFAULT_GROUP_MEDIUM,
            rate_medium: DEFAULT_RATE_MEDIUM,
            demote_samples: DEFAULT_DEMOTE_SAMPLES,
        }
    }
}

/// 实时负载指标（由传输层/会话层周期性喂入）。
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub group_size: u32,
    pub msg_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngine {
    pub thresholds: Thresholds,
    /// Some(t) = 用户手动锁档，监控指标被忽略。
    pub locked: Option<Tier>,
    current: Tier,
    below_count: u32,
}

impl PolicyEngine {
    pub fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            locked: None,
            current: Tier::Light,
            below_count: 0,
        }
    }

    pub fn current(&self) -> Tier {
        self.locked.unwrap_or(self.current)
    }

    fn demanded(&self, m: Metrics) -> Tier {
        let t = &self.thresholds;
        // 非有限速率（NaN/Inf）fail-closed 视为极端负载——
        // 异常指标宁可过度配（Heavy），绝不 fail-open 到轻载
        let rate = if m.msg_rate.is_finite() { m.msg_rate } else { f32::INFINITY };
        let high_load = m.group_size > t.group_medium || rate > t.rate_medium;
        let extreme_load = m.group_size > t.group_medium.saturating_mul(4)
            || rate > t.rate_medium * 4.0;
        if extreme_load {
            Tier::Heavy
        } else if high_load {
            Tier::Medium
        } else {
            Tier::Light
        }
    }

    /// 喂入新指标，返回本采样周期应生效的档位。
    /// 升档即时（宁可过度配，可跳级）；降档**逐级**——每持续低载一个
    /// demote_samples 周期降一级（Heavy→Medium→Light）。
    pub fn observe(&mut self, m: Metrics) -> Tier {
        if self.locked.is_some() {
            return self.current();
        }
        let want = self.demanded(m);
        if want > self.current {
            self.current = want;
            self.below_count = 0;
        } else if want < self.current {
            self.below_count += 1;
            if self.below_count >= self.thresholds.demote_samples {
                self.current = match self.current {
                    Tier::Heavy => Tier::Medium,
                    Tier::Medium => Tier::Light,
                    Tier::Light => Tier::Light,
                };
                self.below_count = 0;
            }
        } else {
            self.below_count = 0;
        }
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(Thresholds::default())
    }

    #[test]
    fn light_by_default() {
        let mut e = engine();
        assert_eq!(e.observe(Metrics { group_size: 10, msg_rate: 1.0 }), Tier::Light);
    }

    #[test]
    fn promotes_on_group_size_or_rate() {
        let mut e = engine();
        assert_eq!(e.observe(Metrics { group_size: 60, msg_rate: 1.0 }), Tier::Medium);
        let mut e2 = engine();
        assert_eq!(e2.observe(Metrics { group_size: 10, msg_rate: 25.0 }), Tier::Medium);
    }

    #[test]
    fn promotes_to_heavy_at_4x() {
        let mut e = engine();
        assert_eq!(e.observe(Metrics { group_size: 201, msg_rate: 1.0 }), Tier::Heavy);
        let mut e2 = engine();
        assert_eq!(e2.observe(Metrics { group_size: 10, msg_rate: 100.0 }), Tier::Heavy);
    }

    #[test]
    fn demotion_requires_sustained_low_per_level() {
        let mut e = engine();
        // Heavy 状态：前 4 个低载样本维持 Heavy，第 5 个降为 Medium
        assert_eq!(e.observe(Metrics { group_size: 201, msg_rate: 1.0 }), Tier::Heavy);
        for _ in 0..4 {
            assert_eq!(e.observe(Metrics { group_size: 10, msg_rate: 1.0 }), Tier::Heavy);
        }
        assert_eq!(e.observe(Metrics { group_size: 10, msg_rate: 1.0 }), Tier::Medium);
        // Medium→Light：再需一个完整的持续低载周期
        for _ in 0..4 {
            assert_eq!(e.observe(Metrics { group_size: 10, msg_rate: 1.0 }), Tier::Medium);
        }
        assert_eq!(e.observe(Metrics { group_size: 10, msg_rate: 1.0 }), Tier::Light);
    }

    #[test]
    fn bounce_does_not_flicker() {
        // 高低交替：一次高载升档后，偶发低载不应立即降档
        let mut e = engine();
        e.observe(Metrics { group_size: 60, msg_rate: 1.0 });
        e.observe(Metrics { group_size: 10, msg_rate: 1.0 });
        assert_eq!(e.observe(Metrics { group_size: 60, msg_rate: 1.0 }), Tier::Medium);
    }

    #[test]
    fn manual_lock_overrides_metrics() {
        let mut e = engine();
        e.locked = Some(Tier::Heavy);
        assert_eq!(e.observe(Metrics { group_size: 1, msg_rate: 0.0 }), Tier::Heavy);
        e.locked = Some(Tier::Light);
        assert_eq!(e.observe(Metrics { group_size: 999, msg_rate: 999.0 }), Tier::Light);
    }
}
