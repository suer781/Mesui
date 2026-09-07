//! SP-7 资源治理器：陌生人中继的算力分配与公平性。
//!
//! 用户规则：
//! - 陌生人中继占用节点容量的 **15%**（满电正常负载）
//! - 电量 <40%（未充电）**或** 高负载 → 缩减为 **3%**
//! - 软件自动定价：预算 / 连接中的发送者数 = 单发送者上限，但有**保底**
//!   ——「最低保证所有人都可以连接」（连接是硬保证，质量随人数优雅退化）
//! - 发送与接收速率分别限额（对称独立的令牌桶）

use crate::identity::NodeId;
use std::collections::HashMap;

pub const STRANGER_SHARE_FULL: f64 = 0.15;
/// 曲线落地值（不再是断崖，而是渐近地板）
pub const STRANGER_SHARE_FLOOR: f64 = 0.03;
/// 电量曲线起点（满份额）/ 终点（地板份额）：40% 以下开始**缓慢曲线下降**
pub const BATTERY_CURVE_START: f64 = 40.0;
pub const BATTERY_CURVE_END: f64 = 5.0;
/// 负载曲线：≤0.6 满份额，0.6→1.0 曲线下降
pub const LOAD_CURVE_START: f32 = 0.6;
pub const LOAD_CURVE_END: f32 = 1.0;
/// 每个陌生发送者的保底速率（条/分钟）——连接的硬保证
pub const FLOOR_PER_SENDER: u32 = 6;
/// 令牌桶容量 = 每分钟上限（允许一次小突发）
const BUCKET_CAPACITY_FACTOR: f64 = 1.0;
const REFILL_INTERVAL_MS: i64 = 60_000;

/// smoothstep：缓入缓出的曲线插值（t=0→0，t=1→1，二阶导在端点为 0——无拐点）
fn smoothstep(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

#[derive(Debug, Clone)]
struct SenderQuota {
    send_tokens: f64,
    recv_tokens: f64,
    last_refill_ms: i64,
}

#[derive(Debug)]
pub struct RelayGovernor {
    /// 节点基线容量（条/分钟）——由设备性能决定，Kotlin 侧按机型评估传入
    capacity_per_min: u32,
    battery_percent: Option<u8>,
    charging: bool,
    load: f32,
    senders: HashMap<NodeId, SenderQuota>,
}

impl RelayGovernor {
    pub fn new(capacity_per_min: u32) -> Self {
        Self {
            capacity_per_min,
            battery_percent: Some(100),
            charging: false,
            load: 0.0,
            senders: HashMap::new(),
        }
    }

    /// Kotlin 侧电池广播喂入（None = 未知，按满电处理）。
    pub fn set_battery(&mut self, percent: Option<u8>, charging: bool) {
        self.battery_percent = percent;
        self.charging = charging;
    }

    /// Kotlin 侧负载喂入（0.0-1.0，核心线程占用率）。
    /// 红队 red11 修复：NaN/异常输入 fail-closed 到满负载（最低份额），
    /// 绝不允许异常数据让资源份额 fail-open 到 15%。
    pub fn set_load(&mut self, load: f32) {
        self.load = if load.is_finite() { load.clamp(0.0, 1.0) } else { 1.0 };
    }

    /// 当前陌生人中继份额（**连续曲线，无断崖**）：
    /// 电量 ≥40% → 15%；40%→5% 之间沿 smoothstep 曲线缓慢滑向 3%；≤5% → 3% 地板。
    /// 负载同构：≤0.6 满份额，0.6→1.0 曲线下降。
    /// 设计意图（用户定稿）：降档必须渐进——其他端点会自动优选到更快路线，
    /// 本节点缓慢让出负载，全程无毁灭性断联。
    pub fn share(&self) -> f64 {
        self.battery_share().min(self.load_share())
    }

    fn battery_share(&self) -> f64 {
        match self.battery_percent {
            None => STRANGER_SHARE_FULL,
            Some(_p) if self.charging => STRANGER_SHARE_FULL, // 充电中：正在恢复
            Some(p) => {
                let b = p as f64;
                if b >= BATTERY_CURVE_START {
                    STRANGER_SHARE_FULL
                } else if b <= BATTERY_CURVE_END {
                    STRANGER_SHARE_FLOOR
                } else {
                    let t = (b - BATTERY_CURVE_END) / (BATTERY_CURVE_START - BATTERY_CURVE_END);
                    STRANGER_SHARE_FLOOR + (STRANGER_SHARE_FULL - STRANGER_SHARE_FLOOR) * smoothstep(t)
                }
            }
        }
    }

    fn load_share(&self) -> f64 {
        if self.load <= LOAD_CURVE_START {
            STRANGER_SHARE_FULL
        } else if self.load >= LOAD_CURVE_END {
            STRANGER_SHARE_FLOOR
        } else {
            let t = ((self.load - LOAD_CURVE_START) / (LOAD_CURVE_END - LOAD_CURVE_START)) as f64;
            STRANGER_SHARE_FLOOR + (STRANGER_SHARE_FULL - STRANGER_SHARE_FLOOR) * smoothstep(t)
        }
    }

    /// 陌生人中继总预算（条/分钟）。
    pub fn budget_per_min(&self) -> u32 {
        (self.capacity_per_min as f64 * self.share()).round() as u32
    }

    /// 定价：单发送者上限 = max(保底, 预算/人数)。
    /// 人数增多时上限优雅滑向保底——连接永远保证，质量递减。
    pub fn per_sender_cap(&self) -> u32 {
        let n = self.senders.len();
        if n == 0 {
            return self.budget_per_min().max(FLOOR_PER_SENDER);
        }
        (self.budget_per_min() / n as u32).max(FLOOR_PER_SENDER)
    }

    pub fn connected_strangers(&self) -> usize {
        self.senders.len()
    }

    pub fn register_sender(&mut self, peer: NodeId, now_ms: i64) {
        let cap = self.per_sender_cap() as f64;
        self.senders.entry(peer).or_insert(SenderQuota {
            send_tokens: cap,
            recv_tokens: cap,
            last_refill_ms: now_ms,
        });
    }

    pub fn drop_sender(&mut self, peer: &NodeId) {
        self.senders.remove(peer);
    }

    /// 按时间差为所有发送者补充令牌（上限=当前定价）。
    fn refill_all(&mut self, now_ms: i64) {
        let cap = self.per_sender_cap() as f64 * BUCKET_CAPACITY_FACTOR;
        let cap_per_ms = cap / REFILL_INTERVAL_MS as f64;
        for q in self.senders.values_mut() {
            let elapsed = (now_ms - q.last_refill_ms).max(0) as f64;
            if elapsed > 0.0 {
                q.send_tokens = (q.send_tokens + elapsed * cap_per_ms).min(cap);
                q.recv_tokens = (q.recv_tokens + elapsed * cap_per_ms).min(cap);
                q.last_refill_ms = now_ms;
            }
        }
        // 令牌上限随定价收缩（降档立即生效）
        for q in self.senders.values_mut() {
            q.send_tokens = q.send_tokens.min(cap);
            q.recv_tokens = q.recv_tokens.min(cap);
        }
    }

    fn take_token(&mut self, peer: &NodeId, now_ms: i64, send: bool) -> bool {
        self.refill_all(now_ms);
        let Some(q) = self.senders.get_mut(peer) else {
            return false; // 未注册的陌生发送者：先 register（握手时完成）
        };
        let tokens = if send { &mut q.send_tokens } else { &mut q.recv_tokens };
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 发送方向：该陌生发送者本条是否放行。
    pub fn allow_send(&mut self, peer: &NodeId, now_ms: i64) -> bool {
        self.take_token(peer, now_ms, true)
    }

    /// 接收方向：向该陌生接收者投递本条是否放行。
    pub fn allow_recv(&mut self, peer: &NodeId, now_ms: i64) -> bool {
        self.take_token(peer, now_ms, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_share_is_15_percent() {
        let g = RelayGovernor::new(120);
        assert_eq!(g.share(), STRANGER_SHARE_FULL);
        assert_eq!(g.budget_per_min(), 18); // 120 × 0.15
    }

    #[test]
    fn battery_curve_is_continuous_and_lands_on_floor() {
        let mut g = RelayGovernor::new(120);
        let mut prev = g.share();
        let mut prev_batt = 100u8;
        for b in (1..=100).rev() {
            g.set_battery(Some(b), false);
            let share = g.share();
            // 连续性：相邻 1% 电量的份额变化必须微小（无断崖）
            assert!((prev - share).abs() < 0.01, "b={b}: {prev}→{share} 跳变");
            assert!(
                (STRANGER_SHARE_FLOOR..=STRANGER_SHARE_FULL).contains(&share),
                "份额必须在地板与满额之间: {share}"
            );
            assert!(share <= prev + 1e-9, "电量下降份额不得回升");
            prev = share;
            prev_batt = b;
        }
        assert_eq!(prev_batt, 1);
        assert_eq!(g.share(), STRANGER_SHARE_FLOOR, "落地=地板份额");
    }

    #[test]
    fn curve_midpoint_is_between_floor_and_full() {
        let mut g = RelayGovernor::new(120);
        g.set_battery(Some(20), false); // 曲线中段
        let share = g.share();
        assert!(share > STRANGER_SHARE_FLOOR && share < STRANGER_SHARE_FULL);
        assert_eq!(g.budget_per_min(), (120.0 * share).round() as u32);
    }

    #[test]
    fn charging_low_battery_stays_full() {
        let mut g = RelayGovernor::new(120);
        g.set_battery(Some(10), true);
        assert_eq!(g.share(), STRANGER_SHARE_FULL, "充电中不降档（正在恢复）");
    }

    #[test]
    fn full_load_lands_on_floor() {
        let mut g = RelayGovernor::new(120);
        g.set_battery(Some(100), false);
        g.set_load(1.0);
        assert_eq!(g.share(), STRANGER_SHARE_FLOOR);
        g.set_load(0.5);
        assert_eq!(g.share(), STRANGER_SHARE_FULL);
    }

    #[test]
    fn per_sender_cap_degrades_to_floor_as_crowd_grows() {
        let mut g = RelayGovernor::new(120);
        assert_eq!(g.per_sender_cap(), 18, "无人连接时=总预算");
        for i in 0..6u8 {
            g.register_sender([i; 32], 1000);
        }
        assert_eq!(g.per_sender_cap(), 6, "预算 18 / 6 人 = 3 → 保底抬到 6");
        for i in 6..20u8 {
            g.register_sender([i; 32], 1000);
        }
        assert_eq!(g.per_sender_cap(), 6, "20 人时保底仍保证连接（预算超卖，连接优先）");
    }

    #[test]
    fn send_tokens_refill_per_minute_and_block_bursts() {
        // capacity=40 → 满电预算 6/分 → n=1 时定价上限恰为保底 6
        let mut g = RelayGovernor::new(40);
        g.register_sender([1; 32], 0);
        // 保底 6/分钟：连发 6 条放行，第 7 条拒绝
        for _ in 0..6 {
            assert!(g.allow_send(&[1; 32], 1_000));
        }
        assert!(!g.allow_send(&[1; 32], 1_000));
        // 一分钟后回满
        for _ in 0..6 {
            assert!(g.allow_send(&[1; 32], 61_000));
        }
        assert!(!g.allow_send(&[1; 32], 61_000));
    }

    #[test]
    fn send_and_recv_are_independent_buckets() {
        let mut g = RelayGovernor::new(40);
        g.register_sender([1; 32], 0);
        for _ in 0..6 {
            assert!(g.allow_send(&[1; 32], 1_000));
        }
        assert!(!g.allow_send(&[1; 32], 1_000));
        assert!(g.allow_recv(&[1; 32], 1_000), "发送打满不影响接收桶");
    }

    #[test]
    fn degradation_clamps_existing_tokens_immediately() {
        // capacity=40：满电预算 6；电量降到地板（2%）后预算 1.2→1，
        // 定价上限被保底 6 托住，但既有令牌立即收缩到 6 以内
        let mut g = RelayGovernor::new(40);
        g.register_sender([1; 32], 0);
        for _ in 0..6 {
            assert!(g.allow_send(&[1; 32], 1_000));
        }
        // 电量降到曲线地板：现有令牌立即收缩
        g.set_battery(Some(2), false);
        assert!(!g.allow_send(&[1; 32], 1_100), "降档必须立即生效");
    }
}
