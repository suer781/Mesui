//! 熵源 EntropyHarvester：
//! 主源 = 内核 CSPRNG（getrandom，由硬件熵播种）；
//! 增强层 = 传感器噪声（Kotlin 侧采集后经 `mix()` 注入）BLAKE3 连续搅拌。
//! 安全性永不单独依赖增强层：draw = OS 随机 ⊕ 池状态 的 XOF 派生。

use crate::{CoreError, Result};

pub struct EntropyHarvester {
    pool: blake3::Hasher,
    draws: u64,
}

impl EntropyHarvester {
    pub fn new() -> Result<Self> {
        let mut pool = blake3::Hasher::new();
        pool.update(b"dc-entropy-v1");
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| CoreError::Entropy(e.to_string()))?;
        pool.update(&seed);
        Ok(Self { pool, draws: 0 })
    }

    /// 增强熵注入（传感器抖动、事件时序等）。任意垃圾输入都是安全的。
    pub fn mix(&mut self, data: &[u8]) {
        self.pool.update(&(data.len() as u64).to_be_bytes());
        self.pool.update(data);
    }

    /// 抽取随机字节：OS CSPRNG 为主源，池状态增强混合。
    pub fn draw(&mut self, out: &mut [u8]) -> Result<()> {
        let mut fresh = [0u8; 32];
        getrandom::fill(&mut fresh).map_err(|e| CoreError::Entropy(e.to_string()))?;
        self.mix(&fresh);
        self.draws = self.draws.wrapping_add(1);
        self.pool.update(&self.draws.to_be_bytes());
        self.pool.finalize_xof().fill(out);
        Ok(())
    }

    /// 512 位真随机 token（添加好友挑战等场景的最低规格）。
    pub fn token512(&mut self) -> Result<[u8; 64]> {
        let mut t = [0u8; 64];
        self.draw(&mut t)?;
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_never_repeat() {
        let mut h = EntropyHarvester::new().unwrap();
        let mut prev = [1u8; 64];
        for _ in 0..64 {
            let mut next = [0u8; 64];
            h.draw(&mut next).unwrap();
            assert_ne!(next, prev);
            prev.copy_from_slice(&next);
        }
    }

    #[test]
    fn token512_len_and_uniqueness() {
        let mut h = EntropyHarvester::new().unwrap();
        let a = h.token512().unwrap();
        let b = h.token512().unwrap();
        assert_eq!(a.len(), 64); // 512 bit
        assert_ne!(a, b);
    }

    #[test]
    fn sensor_garbage_is_safe() {
        let mut h = EntropyHarvester::new().unwrap();
        let mut a = [0u8; 32];
        h.draw(&mut a).unwrap();
        h.mix(b"accelerometer jitter 0.0123,0.9981,...");
        let mut b = [0u8; 32];
        h.draw(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
