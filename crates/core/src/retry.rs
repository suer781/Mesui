//! 重试策略：指数退避 + 全抖动（full jitter，AWS 同款公开模式）。
//!
//! 职责边界：本模块只做**纯计算**（第 n 次失败后该等多久、是否已耗尽）；
//! 持久化在 queue.rs（next_attempt_ms + 死信），驱动在阶段 4/5 通道状态机
//! （每次传输失败 → schedule_retry / exhausted → dead_letter）。

use crate::{CoreError, Result};

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// 最大尝试次数（含首次），超过即死信
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // 默认 8 次、2s 起、上限 15 分钟：蓝牙/中继的合理节奏
        Self { max_attempts: 8, base_delay_ms: 2_000, max_delay_ms: 15 * 60_000 }
    }
}

impl RetryPolicy {
    /// 第 attempt 次失败（attempt ≥ 1）后的等待毫秒数。
    /// 全抖动：在 [base, min(base·2^(attempt-1), max)] 内均匀随机——
    /// 防止大量节点同拍重试形成自同步风暴（去中心化软件尤其要防这个）。
    pub fn next_delay_ms(&self, attempt: u32) -> Result<u64> {
        if attempt == 0 {
            return Err(CoreError::Config("attempt starts at 1".into()));
        }
        if attempt >= self.max_attempts {
            return Err(CoreError::Config("attempts exhausted, no next delay".into()));
        }
        let shift = (attempt - 1).min(20); // 防 u64 溢出，上限已由 max_delay 兜底
        let exp = self
            .base_delay_ms
            .saturating_mul(1u64 << shift);
        let cap = exp.min(self.max_delay_ms).max(self.base_delay_ms);
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).map_err(|e| CoreError::Entropy(e.to_string()))?;
        let span = cap - self.base_delay_ms + 1;
        let jitter = u64::from_be_bytes(buf) % span;
        Ok(self.base_delay_ms + jitter)
    }

    pub fn exhausted(&self, attempts: u32) -> bool {
        attempts >= self.max_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_grows_exponentially_within_cap() {
        let p = RetryPolicy::default();
        // 多次采样验证上界与下界（抖动随机）
        for attempt in 1u32..7 {
            for _ in 0..32 {
                let d = p.next_delay_ms(attempt).unwrap();
                assert!(d >= p.base_delay_ms);
                let cap = p
                    .base_delay_ms
                    .saturating_mul(1u64 << (attempt - 1))
                    .min(p.max_delay_ms);
                assert!(d <= cap, "attempt={attempt} delay={d} cap={cap}");
            }
        }
        // 后期一律贴近 max_delay
        for _ in 0..16 {
            let d = p.next_delay_ms(7).unwrap();
            assert!(d >= p.base_delay_ms && d <= p.max_delay_ms);
        }
    }

    #[test]
    fn jitter_avoids_synchronized_retries() {
        let p = RetryPolicy::default();
        let d1 = p.next_delay_ms(3).unwrap();
        let mut differs = false;
        for _ in 0..16 {
            if p.next_delay_ms(3).unwrap() != d1 {
                differs = true;
                break;
            }
        }
        assert!(differs, "全抖动不应产生固定值");
    }

    #[test]
    fn exhaustion_and_guards() {
        let p = RetryPolicy::default();
        assert!(!p.exhausted(0));
        assert!(!p.exhausted(7));
        assert!(p.exhausted(8));
        assert!(p.next_delay_ms(0).is_err());
        assert!(p.next_delay_ms(8).is_err());
    }
}
