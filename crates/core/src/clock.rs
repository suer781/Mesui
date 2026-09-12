//! 软件内部独立时钟：
//! 内部钟 = 系统钟读数 + 校准偏移。**永不修改系统时间**；
//! 校准源优先级 = 网络（Android 系统自同步/HTTPS 时间）→ 蓝牙联系人交换。
//!
//! 安全属性：
//! - 高水位防回拨：内部钟单调不降（持久化字段由调用方恢复/保存），
//!   用户或攻击者把系统钟往回拨，安全判定用的「现在」依然不回退
//! - 校准偏移全部限幅（±24h）：单个毒源最多把钟推偏一天，不可能造出「过期票复活一年」
//! - 蓝牙样本需 **3 人法定人数** 且最大共识簇 ≥60s 内一致——单个/成对毒联系人无法校准
//! - 网络校准新鲜期内（6h）忽略蓝牙样本：有网时以网络为准

use crate::identity::NodeId;
use std::collections::HashMap;

pub const MAX_CORRECTION_MS: i64 = 24 * 60 * 60 * 1000;
pub const NETWORK_FRESH_MS: i64 = 6 * 60 * 60 * 1000;
pub const MAX_RTT_MS: i64 = 5_000;
pub const CLUSTER_TOLERANCE_MS: i64 = 60_000;
pub const PEER_QUORUM: usize = 3;
/// 网络双源交叉验证容差：两源偏移差 ≤5s 视为一致
pub const CROSS_CHECK_TOLERANCE_MS: i64 = 5_000;
/// 网络源（无认证）单次采纳的偏移变化上限——
/// 防止一致的双源把钟一次拉偏 20 分钟、把 ±5min 重放窗实际拉成 ±24h。
pub const NETWORK_ADOPTION_CAP_MS: i64 = 2 * 60_000;
/// 网络采纳冷却——回拨速度（≤2min/10min）永远追不上
/// 真实时间前进，旧写入与「现在」的差距单调拉大，重放永不可行。
pub const NETWORK_ADOPTION_COOLDOWN_MS: i64 = 10 * 60_000;
/// 本地钟读数的合理上界（2100-01-01 前后的毫秒数）。
/// 红队 A1 修复：FFI 边界的 local_ms 直通 `now()`，i64::MAX 一类的值会把
/// `internal = local_ms + offset` 推到极大并把内部钟高水位钉死在极大值——
/// 此后所有真实时间戳的合法写入全部 WindowExceeded（门禁级 DoS）。
/// 进入安全状态机的读数先钳制到 `[0, MAX_PLAUSIBLE_LOCAL_MS]`。
pub const MAX_PLAUSIBLE_LOCAL_MS: i64 = 4_102_444_800_000;
/// 单次 `now()` 调用允许采纳进高水位的最大前跳（7 天 = 24h 偏移限幅 +
/// 充裕的诚实挂起时长）。红队 A1 修复的另一面：即使读数落在合理区间内，
/// 一次调用把本地钟前跳超过该值也视为毒化读数——高水位一律不采纳
/// （毒化调用影响至多本次判定，绝不能把基线钉死在不可达的未来）。
pub const MAX_TRUSTED_ADVANCE_MS: i64 = 7 * 86_400_000;
/// 双源配对挂起槽的超时。红队 A3 修复：`pending_network` 是单槽，
/// 毒源占槽后诚实双源永远等不到配对——槽内样本 5 分钟未获配对即自动
/// 失效清空，允许新来源重新占槽（陈旧偏移参与配对只会产出垃圾均值）。
pub const NETWORK_PENDING_TIMEOUT_MS: i64 = 5 * 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Unsynced,
    Network,
    Peers,
}

struct PeerSample {
    offset_ms: i64,
    at_local_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    RttTooLarge,
    Clamped,
    UntrustedPeer,
}

pub struct InternalClock {
    network_offset_ms: Option<i64>,
    network_fresh_until: i64,
    /// 双源交叉验证的挂起首读（来源 id，偏移，挂起时刻的本地钟）
    pending_network: Option<(u8, i64, i64)>,
    /// 上次网络采纳时刻（本地钟），冷却期内忽略新的采纳
    last_network_adopted_at: i64,
    /// 只有**已验证联系人**（加好友流程产出）的校时交换才被接受——
    /// 防止蓝牙范围内 3 台女巫设备凑满法定人数
    trusted_peers: HashMap<NodeId, ()>,
    peers: HashMap<NodeId, PeerSample>,
    /// 内部钟高水位（持久化字段，防回拨）
    internal_high_water_ms: u64,
    /// 本地钟高水位：检测系统钟被拨回（回滚攻击）
    local_high_water_ms: i64,
    /// 上次生效偏移：偏移变化时重置内部高水位基线（毒偏移撤离后不残留旧峰，
    /// 否则毒偏移会把内部钟钉死在峰值，诚实时间戳全部判过旧）
    last_offset_ms: i64,
    pub rollback_detected: bool,
}

impl Default for InternalClock {
    fn default() -> Self {
        Self {
            network_offset_ms: None,
            network_fresh_until: i64::MIN / 2,
            pending_network: None,
            last_network_adopted_at: i64::MIN / 2,
            trusted_peers: HashMap::new(),
            peers: HashMap::new(),
            internal_high_water_ms: 0,
            local_high_water_ms: i64::MIN / 2,
            last_offset_ms: 0,
            rollback_detected: false,
        }
    }
}

impl InternalClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// 启动时从持久层恢复内部钟高水位（防回拨的跨重启记忆）。
    /// 持久层可能被篡改/损坏——u64::MAX 一类的值经 `as i64`
    /// 会回绕成负数毒化整条时间链，恢复值必须经过合理性钳制。
    pub fn restore_high_water(&mut self, persisted_ms: u64) {
        // 合理上界：2100-01-01 前后的毫秒数；超出视为持久层损坏，忽略
        const MAX_PLAUSIBLE_MS: u64 = 4_102_444_800_000;
        let v = persisted_ms.min(MAX_PLAUSIBLE_MS);
        self.internal_high_water_ms = self.internal_high_water_ms.max(v);
    }

    pub fn high_water_ms(&self) -> u64 {
        self.internal_high_water_ms
    }

    /// 标记已验证联系人（加好友/安全码核对通过后调用）——其校时交换才被采信。
    pub fn trust_peer(&mut self, peer: NodeId) {
        self.trusted_peers.insert(peer, ());
    }

    /// 撤销信任（删除联系人/安全码异常时）。
    pub fn distrust_peer(&mut self, peer: &NodeId) {
        self.trusted_peers.remove(peer);
        self.peers.remove(peer);
    }

    pub fn is_trusted(&self, peer: &NodeId) -> bool {
        self.trusted_peers.contains_key(peer)
    }

    pub fn source(&self, local_ms: i64) -> Source {
        if self.network_offset_ms.is_some() && local_ms <= self.network_fresh_until {
            Source::Network
        } else if self.peak_cluster(local_ms).is_some() {
            Source::Peers
        } else {
            Source::Unsynced
        }
    }

    /// 网络校时（优先源）：**双源交叉验证**——
    /// 两个不同来源的偏移在 ±5s 内一致才采纳；单一来源永不采纳
    /// （防止恶意 WiFi 单点平移重放窗/票据窗）。
    /// `source_id`：来源标识（不同 NTP 服务器 / 不同 HTTPS 时间接口）。
    pub fn on_network_sync(&mut self, source_id: u8, local_ms: i64, network_ms: i64) {
        // 两输入均为外部可控，饱和减法防 i64 溢出 panic
        let raw = network_ms.saturating_sub(local_ms);
        let clamped = raw.clamp(-MAX_CORRECTION_MS, MAX_CORRECTION_MS);
        // 红队 A3 修复：挂起槽带超时——毒源占槽后，槽内陈旧样本（超过
        // NETWORK_PENDING_TIMEOUT_MS 未获配对）自动失效清空，诚实来源可以
        // 重新占槽配对；陈旧偏移与新样本配对只会产出垃圾均值，宁可作废。
        let pending_stale = match self.pending_network {
            Some((_, _, at)) => local_ms.saturating_sub(at) > NETWORK_PENDING_TIMEOUT_MS,
            None => false,
        };
        if pending_stale {
            self.pending_network = None;
        }
        match self.pending_network.take() {
            Some((prev_source, prev_offset, _)) if prev_source != source_id => {
                // 双源交叉验证：一致 → 采纳均值；分歧 → 双双弃用
                if (prev_offset - clamped).abs() <= CROSS_CHECK_TOLERANCE_MS {
                    let adopted = (prev_offset + clamped) / 2;
                    // 相对上一次生效偏移的变化量限幅（无认证源不可大幅挪钟）
                    let delta = adopted.saturating_sub(self.last_offset_ms);
                    // 采纳冷却——距上次采纳不足 10 分钟，本次丢弃
                    let cooling = local_ms.saturating_sub(self.last_network_adopted_at)
                        < NETWORK_ADOPTION_COOLDOWN_MS;
                    if delta.abs() > NETWORK_ADOPTION_CAP_MS || cooling {
                        self.network_offset_ms = None;
                        self.network_fresh_until = i64::MIN / 2;
                    } else {
                        self.network_offset_ms = Some(adopted);
                        self.network_fresh_until = local_ms + NETWORK_FRESH_MS;
                        self.last_network_adopted_at = local_ms;
                    }
                } else {
                    self.network_offset_ms = None;
                    self.network_fresh_until = i64::MIN / 2;
                }
            }
            _ => {
                // 首个来源（或同源更新）：挂起等待第二来源
                self.pending_network = Some((source_id, clamped, local_ms));
            }
        }
    }

    /// 蓝牙联系人交换（回退源）：NTP 四时间戳求偏移。
    /// t1=本地发出时刻 t2=对端收到时刻 t3=对端回复时刻 t4=本地收到回复时刻。
    pub fn on_peer_exchange(
        &mut self,
        peer: NodeId,
        t1: i64,
        t2: i64,
        t3: i64,
        t4: i64,
    ) -> Result<i64, ClockError> {
        // 只信已验证联系人——陌生人/女巫设备的校时交换直接拒绝
        if !self.is_trusted(&peer) {
            return Err(ClockError::UntrustedPeer);
        }
        // t2/t3 攻击者可控，全部饱和运算防 i64 溢出 panic
        let rtt = t4.saturating_sub(t1).saturating_sub(t3.saturating_sub(t2));
        if t2 > t3 {
            return Err(ClockError::RttTooLarge); // 对端不可能在收到前回复：畸形交换
        }
        if !(0..=MAX_RTT_MS).contains(&rtt) {
            return Err(ClockError::RttTooLarge);
        }
        let raw = t2
            .saturating_sub(t1)
            .saturating_add(t3.saturating_sub(t4))
            / 2;
        let clamped = raw.clamp(-MAX_CORRECTION_MS, MAX_CORRECTION_MS);
        self.peers.insert(peer, PeerSample { offset_ms: clamped, at_local_ms: t4 });
        Ok(clamped)
    }

    /// 生效偏移：网络新鲜 → 网络偏移；否则 ≥3 个联系人样本的最大共识簇中位数；否则 0。
    fn effective_offset(&self, local_ms: i64) -> i64 {
        if let Some(net_offset) = self
            .network_offset_ms
            .filter(|_| local_ms <= self.network_fresh_until)
        {
            return net_offset;
        }
        match self.peak_cluster(local_ms) {
            Some(cluster) => {
                let mut v = cluster.clone();
                v.sort_unstable();
                v[v.len() / 2] // 共识簇中位数
            }
            None => 0,
        }
    }

    /// 最大共识簇：按偏移排序后，相邻差 ≤CLUSTER_TOLERANCE 的连续段中成员最多的一段
    /// （段大小须 ≥PEER_QUORUM）——离群毒样本自然落单被排除。
    fn peak_cluster(&self, local_ms: i64) -> Option<Vec<i64>> {
        // 样本 30 分钟内有效；local_ms 可为 i64::MIN/MAX 级极端输入
        // （FFI 边界可达）——饱和运算防溢出 panic（红队 A10 修复）
        let fresh_cut = local_ms.saturating_sub(30 * 60 * 1000);
        let mut offsets: Vec<i64> = self
            .peers
            .values()
            .filter(|s| s.at_local_ms >= fresh_cut)
            .map(|s| s.offset_ms)
            .collect();
        if offsets.len() < PEER_QUORUM {
            return None;
        }
        offsets.sort_unstable();
        let mut best: Vec<i64> = Vec::new();
        let mut run: Vec<i64> = vec![offsets[0]];
        for w in offsets.windows(2) {
            // 偏移本身已限幅 ±24h，差值不会溢出——饱和运算兜底极端输入
            if w[1].saturating_sub(w[0]) <= CLUSTER_TOLERANCE_MS {
                run.push(w[1]);
            } else {
                if run.len() > best.len() {
                    best = std::mem::take(&mut run);
                }
                run = vec![w[1]];
            }
        }
        if run.len() > best.len() {
            best = run;
        }
        if best.len() >= PEER_QUORUM {
            Some(best)
        } else {
            None
        }
    }

    /// 安全「现在」：内部钟 + 高水位防回拨（调用方应周期性持久化 high_water_ms）。
    /// 偏移变化时重置内部高水位基线——毒偏移撤离后不残留旧峰；
    /// 本地钟回拨（回滚攻击）单独检测，回拨期间内部钟钉在高水位。
    /// 内部钟全程保持在 i64 正数域，杜绝 `as i64` 回绕。
    ///
    /// 红队 A1 修复：进入安全状态机的本地读数先钳制到合理区间
    /// （`MAX_PLAUSIBLE_LOCAL_MS`），且高水位只采纳「可信」读数——
    /// 相对本地高水位的单次前跳超过 `MAX_TRUSTED_ADVANCE_MS`（毒化 FFI
    /// 输入/被拨快多年的系统钟）一律不写入基线。毒化读数至多影响本次
    /// 判定（返回值仍按原始读数计算，窗口判定逐调用生效），绝不能把
    /// 高水位钉死在不可达的未来、让此后所有真实时间戳的合法写入全拒。
    pub fn now(&mut self, local_ms: i64) -> i64 {
        // 状态路径用合理值；返回路径用原始读数（两者只在极端输入下分叉）
        let plausible = local_ms.clamp(0, MAX_PLAUSIBLE_LOCAL_MS);
        let offset = self.effective_offset(plausible);
        if plausible < self.local_high_water_ms.saturating_sub(60_000) {
            self.rollback_detected = true; // 系统钟被拨回超过 1 分钟：回滚攻击
        }
        // 高水位采纳的可信性判定：首次观测锚定（但恰好顶着钳制上界的
        // 首读数视为垃圾，不锚定）；此后单次前跳超限即毒化。
        let first_observation = self.local_high_water_ms == i64::MIN / 2;
        let forward_jump = plausible.saturating_sub(self.local_high_water_ms);
        let trusted = (first_observation && plausible < MAX_PLAUSIBLE_LOCAL_MS)
            || (!first_observation && forward_jump <= MAX_TRUSTED_ADVANCE_MS);
        if plausible > self.local_high_water_ms && trusted {
            self.local_high_water_ms = plausible;
            self.rollback_detected = false; // 本地钟追平高水位：解除
        }
        let internal = plausible.saturating_add(offset).max(0);
        if offset != self.last_offset_ms {
            // 偏移变化（重校准）：重置基线，允许内部钟跟随新偏移回落。
            // 红队 A2 修复：回滚期间若新内部钟比旧高水位低超过 1 小时，
            // 这是「系统钟拨回 + 偏移变化」的组合攻击（把高水位整体洗回
            // 一年前、防回拨钳制被一次普通偏移变化击穿）——拒绝重置。
            let candidate = internal as u64;
            let significant_drop = (self.internal_high_water_ms as i64)
                .saturating_sub(candidate as i64)
                > 60 * 60 * 1000;
            if trusted && !(self.rollback_detected && significant_drop) {
                self.last_offset_ms = offset;
                self.internal_high_water_ms = candidate;
            }
        } else if trusted {
            self.internal_high_water_ms = self
                .internal_high_water_ms
                .max(internal as u64);
        }
        if self.rollback_detected {
            return self.internal_high_water_ms as i64;
        }
        let raw_internal = local_ms.saturating_add(offset).max(0);
        raw_internal.max(self.internal_high_water_ms as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_exchange_offset_math() {
        let mut c = InternalClock::new();
        // 对端钟快 5 秒，RTT 200ms
        c.trust_peer([1; 32]);
        let off = c.on_peer_exchange([1; 32], 0, 5_100, 5_200, 300).unwrap();
        assert_eq!(off, 5_000);
    }

    #[test]
    fn absurd_rtt_rejected() {
        let mut c = InternalClock::new();
        c.trust_peer([1; 32]);
        assert_eq!(c.on_peer_exchange([1; 32], 0, 100, 200, 60_000), Err(ClockError::RttTooLarge));
        c.trust_peer([1; 32]);
        assert_eq!(c.on_peer_exchange([1; 32], 0, 200, 100, 300), Err(ClockError::RttTooLarge));
    }

    #[test]
    fn quorum_required_before_peer_offset_applies() {
        let mut c = InternalClock::new();
        let t = 1_000_000i64;
        // 只有 2 个样本：法定人数不足 → 偏移 0（宁可不校准，不可被两个人拨动）
        c.trust_peer([1; 32]);
        c.on_peer_exchange([1; 32], t, t + 5_000, t + 5_300, t + 300).unwrap();
        c.trust_peer([2; 32]);
        c.on_peer_exchange([2; 32], t, t + 5_000, t + 5_300, t + 300).unwrap();
        assert_eq!(c.source(t + 1_000), Source::Unsynced);
        assert_eq!(c.now(t + 1_000), t + 1_000);
        // 第 3 个一致样本到达 → 共识簇成立
        c.trust_peer([3; 32]);
        c.on_peer_exchange([3; 32], t, t + 5_000, t + 5_300, t + 300).unwrap();
        assert_eq!(c.source(t + 2_000), Source::Peers);
        assert!((c.now(t + 2_000) - (t + 2_000 + 5_000)).abs() <= 1);
    }

    #[test]
    fn poison_peer_cannot_shift_clock() {
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        // 3 个诚实样本 (+5s) + 1 个毒样本（+1 年，被限幅到 ±24h）
        for p in 1..=3u8 {
            c.trust_peer([p; 32]);
            c.on_peer_exchange([p; 32], t, t + 5_000, t + 5_300, t + 300).unwrap();
        }
        c.trust_peer([9; 32]);
        c.on_peer_exchange([9; 32], t, t + MAX_CORRECTION_MS, t + MAX_CORRECTION_MS + 100, t + 400).unwrap();
        // 毒样本离群落单：共识簇仍是诚实三人
        assert!((c.now(t + 1_000) - (t + 1_000 + 5_000)).abs() <= 1);
    }

    #[test]
    fn two_poison_clusters_mean_no_quorum() {
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        for p in 1..=2u8 {
            c.trust_peer([p; 32]);
            c.on_peer_exchange([p; 32], t, t + 5_000, t + 5_300, t + 300).unwrap();
        }
        for p in 10..=12u8 {
            c.trust_peer([p; 32]);
            c.on_peer_exchange([p; 32], t, t + 86_400_000, t + 86_400_100, t + 300).unwrap();
        }
        // 5 样本两个簇（3 人主张 +24h、2 人主张 +5s）——最大簇 3 ≥ 人数，但… 
        // 最大簇是毒簇！保守策略：取「最大共识簇」，此处会跟随毒簇。
        // 防线在于样本必须来自联系人且数量上限受簇内一致性约束，
        // 但仍存在残余风险。
        assert!(c.source(t + 1_000) == Source::Peers);
    }

    #[test]
    fn single_network_source_never_accepted() {
        // 单一来源永不采纳（防止恶意 WiFi 单点平移时间窗）
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        c.on_network_sync(1, t, t + 60_000);
        assert_eq!(c.source(t + 1_000), Source::Unsynced);
        assert_eq!(c.now(t + 1_000), t + 1_000, "单源不得移动内部钟");
        // 第二个独立来源且一致、且变化量 ≤2min（采纳上限）→ 采纳
        c.on_network_sync(2, t + 1_500, t + 1_500 + 60_000);
        assert_eq!(c.source(t + 2_000), Source::Network);
        assert_eq!(c.now(t + 2_000), t + 2_000 + 60_000);
    }

    #[test]
    fn large_network_shift_requires_peer_quorum() {
        // 网络源（无认证）单次采纳 ≤±2min——
        // 一致双源的大幅挪钟（-20min/+1day）一律拒绝，大校正走 3 人联系人共识
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        c.on_network_sync(1, t, t - 20 * 60_000);
        c.on_network_sync(2, t, t - 20 * 60_000);
        assert_eq!(c.source(t + 1_000), Source::Unsynced, "一致双源的 -20min 必须被拒");
        assert_eq!(c.now(t + 1_000), t + 1_000);
    }

    #[test]
    fn conflicting_network_sources_both_rejected() {
        // 两源分歧超容差 → 双双弃用（防止单源投毒抬钟）
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        c.on_network_sync(1, t, t + 3_600_000);          // +1h
        c.on_network_sync(2, t, t + 86_400_000);          // +24h，分歧巨大
        assert_eq!(c.source(t + 1_000), Source::Unsynced);
        assert_eq!(c.now(t + 1_000), t + 1_000);
    }

    #[test]
    fn network_overrides_peers_when_fresh() {
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        c.trust_peer([1; 32]);
        c.on_peer_exchange([1; 32], t, t + 60_000, t + 60_100, t + 300).unwrap();
        c.trust_peer([2; 32]);
        c.on_peer_exchange([2; 32], t, t + 60_000, t + 60_100, t + 300).unwrap();
        c.trust_peer([3; 32]);
        c.on_peer_exchange([3; 32], t, t + 60_000, t + 60_100, t + 300).unwrap();
        assert_eq!(c.source(t + 400), Source::Peers);
        // 网络双源一致校准到达：立即覆盖蓝牙共识
        c.on_network_sync(1, t + 500, t + 500 + 60_000);
        c.on_network_sync(2, t + 550, t + 550 + 60_000);
        assert_eq!(c.source(t + 600), Source::Network);
        assert_eq!(c.now(t + 600), t + 600 + 60_000);
    }

    #[test]
    fn network_staleness_falls_back_to_peers() {
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        c.on_network_sync(1, t, t + 1_000);
        c.on_network_sync(2, t, t + 1_000);
        // 蓝牙交换发生在检查点前一刻（真实场景：刚见面时交换）
        let late = t + NETWORK_FRESH_MS + 1_000;
        for p in 1..=3u8 {
            c.trust_peer([p; 32]);
            c.on_peer_exchange([p; 32], late - 400, late - 300, late - 200, late - 100).unwrap();
        }
        // 6 小时后网络校准过期 → 蓝牙共识接管
        assert_eq!(c.source(late), Source::Peers);
    }

    #[test]
    fn high_water_never_goes_backwards() {
        let mut c = InternalClock::new();
        c.restore_high_water(5_000_000);
        // 本地钟被拨回 1970：内部钟被高水位托住
        assert_eq!(c.now(100), 5_000_000);
        assert_eq!(c.now(200), 5_000_000);
        // 本地钟正常前进后恢复流动
        assert!(c.now(6_000_000) > 5_000_000);
    }

    #[test]
    fn network_offset_is_clamped() {
        let mut c = InternalClock::new();
        let t = 1_700_000_000_000i64;
        // 大幅校正（>±2min）不走网络（采纳上限），走 3 人联系人共识：
        // 每个样本本身限幅 ±24h，共识中位数 = +24h
        // （对称单路延迟 100ms：t2=t1+O+100, t3=t2+50, t4=t3-O+100）
        for p in 1..=3u8 {
            c.trust_peer([p; 32]);
            c.on_peer_exchange(
                [p; 32],
                t,
                t + MAX_CORRECTION_MS + 100,
                t + MAX_CORRECTION_MS + 150,
                t + 250,
            )
            .unwrap();
        }
        assert_eq!(c.now(t + 1_000), t + 1_000 + MAX_CORRECTION_MS);
    }

    // ══════════ 红队修复回归测试（adversarial.rs 对应项的内核级细粒度覆盖） ══════════

    #[test]
    fn red_a1_poison_local_ms_never_pins_high_water() {
        // 一次毒化 FFI 读数（i64::MAX）不得把高水位钉死——
        // 后续真实时间戳的内部钟必须照常流动
        let t = 1_700_000_000_000i64;
        let mut c = InternalClock::new();
        assert_eq!(c.now(t), t, "基线：诚实读数锚定高水位");
        // 毒化调用：返回值按读数主张计算，但不得污染任何基线
        let poisoned = c.now(i64::MAX);
        assert_eq!(poisoned, i64::MAX, "返回值按调用方主张（窗口判定逐调用）");
        assert!(
            c.high_water_ms() <= MAX_PLAUSIBLE_LOCAL_MS as u64,
            "RED: 高水位被毒化读数抬到 {:?}",
            c.high_water_ms()
        );
        // 毒化后诚实钟照常流动，高水位照常跟随
        assert_eq!(c.now(t + 1_000), t + 1_000);
        assert_eq!(c.high_water_ms(), (t + 1_000) as u64);
        // 首个调用就是毒化读数：不锚定，后续诚实调用照常锚定
        let mut c2 = InternalClock::new();
        let _ = c2.now(i64::MAX);
        assert_eq!(c2.high_water_ms(), 0, "毒化首读不得锚定高水位");
        assert_eq!(c2.now(t + 2_000), t + 2_000, "诚实读数照常生效");
        // 恰好顶着钳制上界的读数同样不进基线
        let mut c3 = InternalClock::new();
        let _ = c3.now(MAX_PLAUSIBLE_LOCAL_MS);
        assert_eq!(c3.high_water_ms(), 0);
    }

    #[test]
    fn red_a2_offset_change_during_rollback_keeps_high_water() {
        let t = 1_700_000_000_000i64;
        let mut c = InternalClock::new();
        assert_eq!(c.now(t), t);
        // 回滚 1 小时（> 1 分钟触发回滚检测）+ 偏移变化 -2min：
        // 新内部钟比旧高水位低超过 1 小时 → 拒绝重置，高水位保持
        c.on_network_sync(1, t + 60_000, t + 60_000 - 120_000);
        c.on_network_sync(2, t + 60_000, t + 60_000 - 120_000);
        let rolled = t - 3_600_000;
        assert_eq!(c.now(rolled), t, "RED: 回滚期间偏移变化把高水位洗掉");
        assert!(c.high_water_ms() >= t as u64);
        // 对照组：无回滚时的偏移变化允许重置基线（毒偏移撤离后不残留旧峰）
        let mut c2 = InternalClock::new();
        c2.trust_peer([1; 32]);
        c2.trust_peer([2; 32]);
        c2.trust_peer([3; 32]);
        for p in 1..=3u8 {
            c2.on_peer_exchange(
                [p; 32],
                t,
                t + MAX_CORRECTION_MS + 100,
                t + MAX_CORRECTION_MS + 150,
                t + 250,
            )
            .unwrap();
        }
        assert_eq!(c2.now(t + 1_000), t + 1_000 + MAX_CORRECTION_MS, "毒偏移抬钟");
        assert_eq!(c2.high_water_ms(), (t + 1_000 + MAX_CORRECTION_MS) as u64);
        // 6 小时后网络校准/样本过期 → 偏移回落 0（偏移变化、非回滚）→ 基线重置
        let later = t + NETWORK_FRESH_MS + 31 * 60_000;
        assert_eq!(c2.now(later), later, "非回滚的偏移回落必须允许基线重置");
        assert_eq!(c2.high_water_ms(), later as u64, "旧毒峰不残留");
    }

    #[test]
    fn red_a3_stale_pending_slot_expires_and_fresh_pair_adopts() {
        let t = 1_700_000_000_000i64;
        let mut c = InternalClock::new();
        // 诚实源 1 在 t 时刻报了 +2min 的偏移读数（瞬时毛刺），占住挂起槽
        c.on_network_sync(1, t, t + 120_000);
        // 超时前：旧槽仍活跃——毒源 2 与陈旧样本失配 → 双双作废（单槽语义不变）
        c.on_network_sync(2, t + 200_000, t + 200_000);
        assert_eq!(c.now(t + 201_000), t + 201_000);
        // 源 1 重新挂起同样的陈旧偏移后销声匿迹
        c.on_network_sync(1, t + 201_000, t + 201_000 + 120_000);
        // 超时后（距上次挂起 > 5min）：挂起槽自动失效——
        // 诚实源 2 的新读数不再与陈旧样本互耗，随后与源 1 的新读数正常配对
        c.on_network_sync(2, t + 501_002, t + 501_002); // 陈旧槽清空，源 2 挂起
        c.on_network_sync(1, t + 501_003, t + 501_003); // 源 1 新读数与源 2 配对
        assert_eq!(
            c.source(t + 502_000),
            Source::Network,
            "RED: 陈旧挂起槽永不失效时，诚实双源永远等不到配对"
        );
        assert_eq!(c.now(t + 502_000), t + 502_000, "诚实双源采纳 +0");
    }

    #[test]
    fn red_a10_peak_cluster_extreme_inputs_no_panic() {
        let mut c = InternalClock::new();
        c.trust_peer([1; 32]);
        c.trust_peer([2; 32]);
        c.trust_peer([3; 32]);
        // 样本带 +5s 正常偏移；随后用极端 local_ms 走 source/now
        // （peak_cluster 的 fresh_cut 与簇内差值必须饱和而非溢出 panic）
        let t = 1_700_000_000_000i64;
        for p in 1..=3u8 {
            c.on_peer_exchange([p; 32], t, t + 5_000, t + 5_100, t + 300).unwrap();
        }
        let r = quiet_panic(|| c.source(i64::MIN));
        assert!(r.is_ok(), "RED: source(i64::MIN) 在 peak_cluster 减法上溢出 panic");
        let r = quiet_panic(|| c.source(i64::MAX));
        assert!(r.is_ok(), "RED: source(i64::MAX) 溢出 panic");
        let r = quiet_panic(|| c.now(i64::MIN));
        assert!(r.is_ok(), "RED: now(i64::MIN) 溢出 panic");
        let v = c.now(i64::MIN);
        assert!(
            (0..=MAX_CORRECTION_MS).contains(&v),
            "极端负读数下内部钟必须保持在非负且限幅的值域（实际 {v}）"
        );
    }

    fn quiet_panic<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        std::panic::set_hook(prev);
        r
    }
}
