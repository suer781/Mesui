//! 投递管理器（Phase A「能用」收尾）：把加密队列（queue::Db）与实际发送
//! 通道打通——对方离线时消息滞留队列，到期自动补投，绝不静默丢弃。
//!
//! 职责边界：本模块只做「取件 → 交发 → 记账」的编排；重试节奏在
//! retry::RetryPolicy（纯计算），持久化在 queue::Db（outbox/死信/存档），
//! 实际发送由上层注入的 SendFn 完成（Android = BleMesh/iroh 通道）。
//!
//! 用法（Rust 侧）：
//! ```ignore
//! let db = Db::open(path, Some(key))?;
//! let dm = DeliveryManager::new(db, Box::new(|env| channel_send(env)));
//! // 上层每次 enqueue 后（或前台服务定时器）调：
//! dm.tick(now_ms)?;
//! ```
//! Kotlin 侧经 ffi::DeliveryManagerHandle 注入 SendCallback 并周期 tick。

use crate::envelope::Envelope;
use crate::queue::Db;
use crate::retry::RetryPolicy;
use crate::Result;
use std::sync::Mutex;

/// 上层注入的实际发送函数。
/// - `Ok(true)` = 已送达（通道层已确认）
/// - `Ok(false)` = 对方当前不可达（蓝牙断开 / iroh 未连接）
/// - `Err(msg)` = 通道故障（协议错误、IO 异常）
///
/// 两种失败都走退避重试，区分仅供监控/日志。
pub type SendFn = Box<dyn Fn(&Envelope) -> std::result::Result<bool, String> + Send>;

/// 单拍最多投递条数：防一次 tick 长时间占用发送通道（其余条留待下一拍）。
pub const DEFAULT_BATCH_LIMIT: u32 = 16;

/// 收件去重台账保留窗。queue::prune_seen 红线：窗口不得小于 7 天，
/// 否则旧消息可能被二次接受（重放复活）。
pub const SEEN_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 死信保留窗：给用户 30 天时间在 UI 上手动 revive，过后由 cleanup 清除。
pub const DEAD_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// 一拍投递的结果盘点（测试断言 + Kotlin UI 反馈）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// 本拍实际尝试发送的条数（= 到期取件数）
    pub attempted: u32,
    /// mark_sent 成功数
    pub sent: u32,
    /// Ok(false)：对方不可达数
    pub unreachable: u32,
    /// Err(_)：通道错误数
    pub errored: u32,
    /// 本拍新转死信的条数（重试耗尽）
    pub dead: u32,
}

/// cleanup 的结果盘点。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub pruned_seen: u32,
    pub pruned_dead: u32,
}

/// 队列 ↔ 发送通道的桥。
///
/// 线程模型：Db 底层 rusqlite Connection 非线程安全（!Sync，连带 Arc<Db>
/// 不可跨线程），故 Db 由本类型按值持有、包在 Mutex 内（同 contacts.rs
/// 做法）——DeliveryManager 因此 Send + Sync，可整体放入 UniFFI Object
/// 的 Mutex。tick 的「取件 → 发送 → 记账」全程持有发送锁并串行化，
/// 并发 tick 不会重复投递同一条消息；db 锁按语句短持，发送回调执行期间
/// 不占 db 锁。
pub struct DeliveryManager {
    db: Mutex<Db>,
    send: Mutex<Option<SendFn>>,
    policy: RetryPolicy,
    batch_limit: u32,
}

impl DeliveryManager {
    pub fn new(db: Db, send: SendFn) -> Self {
        Self::with_policy(db, Some(send), RetryPolicy::default(), DEFAULT_BATCH_LIMIT)
    }

    /// 定制重试策略/批量上限（测试用小退避窗，生产用 `new` 的默认值）。
    pub fn with_policy(db: Db, send: Option<SendFn>, policy: RetryPolicy, batch_limit: u32) -> Self {
        Self {
            db: Mutex::new(db),
            send: Mutex::new(send),
            policy,
            batch_limit: batch_limit.max(1),
        }
    }

    /// 重绑发送通道（蓝牙/iroh 重连后调用）。
    pub fn set_send_fn(&self, send: SendFn) {
        *self.send.lock().expect("send mutex poisoned") = Some(send);
    }

    /// 摘除发送通道：tick 变 no-op，消息原样滞留队列（不丢）。
    pub fn clear_send_fn(&self) {
        *self.send.lock().expect("send mutex poisoned") = None;
    }

    /// 队列直通口（enqueue_full / revive / stats / dead_list 等由调用方
    /// 短暂加锁使用）。
    pub fn db(&self) -> &Mutex<Db> {
        &self.db
    }

    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// 投递一拍：取到期消息（pending 且 next_attempt_ms 已到，按创建序），
    /// 逐条交 SendFn；成功 mark_sent，失败（不可达/通道错误）退避重排，
    /// 重试耗尽自动转死信。发送函数未接时为 no-op（消息留在队列等待）。
    ///
    /// 自动发现：上层调 `queue.enqueue*()` 后调一次本方法即触发补投；
    /// 周期调用则由退避节奏（RetryPolicy）控制重试频率。
    pub fn tick(&self, now_ms: u64) -> Result<TickReport> {
        let mut report = TickReport::default();
        let guard = self.send.lock().expect("send mutex poisoned");
        let Some(send) = guard.as_ref() else {
            return Ok(report); // 通道未接：不算失败，消息不丢
        };
        let due = self
            .db
            .lock()
            .expect("db mutex poisoned")
            .due_envelopes(now_ms, self.batch_limit)?;
        // 注意：guard 必须保持存活到循环结束（send 是 guard 的引用）。
        // catch_unwind 保护的是回调 panic，不是锁释放时机。
        for env in due {
            report.attempted += 1;
            // 红队 P1 修复：SendFn 可能 panic（Kotlin 异常经 UniFFI 转换），
            // catch_unwind 防止 Mutex 中毒导致句柄永久不可用
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| send(&env)))
                .unwrap_or(Err("callback panicked".into()));
            match outcome {
                Ok(true) => {
                    self.db.lock().expect("db mutex poisoned").mark_sent(&env.msg_id)?;
                    report.sent += 1;
                }
                Ok(false) => {
                    report.unreachable += 1;
                    if self
                        .db
                        .lock()
                        .expect("db mutex poisoned")
                        .fail_and_reschedule(&env.msg_id, &self.policy, now_ms)?
                    {
                        report.dead += 1;
                    }
                }
                Err(_) => {
                    report.errored += 1;
                    if self
                        .db
                        .lock()
                        .expect("db mutex poisoned")
                        .fail_and_reschedule(&env.msg_id, &self.policy, now_ms)?
                    {
                        report.dead += 1;
                    }
                }
            }
        }
        Ok(report)
    }

    /// 周期清理（低频，如每日一次）：过期去重台账 + 过期死信。
    pub fn cleanup(&self, now_ms: u64) -> Result<CleanupReport> {
        let db = self.db.lock().expect("db mutex poisoned");
        let pruned_seen = db.prune_seen(now_ms.saturating_sub(SEEN_RETENTION_MS))? as u32;
        let pruned_dead = db.prune_dead(now_ms.saturating_sub(DEAD_RETENTION_MS))? as u32;
        Ok(CleanupReport { pruned_seen, pruned_dead })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{MsgId, PayloadKind};
    use crate::identity::Identity;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// 小退避窗（delay ∈ [100, 200] ms）：测试用合成时钟，无真实等待。
    fn small_policy() -> RetryPolicy {
        RetryPolicy { max_attempts: 3, base_delay_ms: 100, max_delay_ms: 200 }
    }

    fn env(msg_id: MsgId, sent_at: u64) -> Envelope {
        let id = Identity::generate().unwrap();
        Envelope {
            msg_id,
            sender: id.node_id(),
            recipient: Some([9; 32]),
            group: None,
            kind: PayloadKind::Text,
            body: vec![1, 2, 3],
            sent_at_ms: sent_at,
            ttl_hops: 6,
        }
    }

    fn db() -> Db {
        Db::open(std::path::Path::new(":memory:"), None).unwrap()
    }

    fn enqueue(dm: &DeliveryManager, e: &Envelope) {
        dm.db().lock().unwrap().enqueue_full(e).unwrap();
    }

    fn stats(dm: &DeliveryManager) -> (u32, u32, u32) {
        dm.db().lock().unwrap().stats().unwrap()
    }

    #[test]
    fn tick_sends_due_and_marks_sent() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let dm = DeliveryManager::new(
            db(),
            Box::new(move |e: &Envelope| {
                seen2.lock().unwrap().push(e.clone());
                Ok(true)
            }),
        );
        let e = env([1; 16], 1000);
        enqueue(&dm, &e);
        // 到期 → 送达 → 出队（新消息 next_attempt_ms=0，入队即到期）
        let r = dm.tick(2000).unwrap();
        assert_eq!(r, TickReport { attempted: 1, sent: 1, ..Default::default() });
        assert_eq!(stats(&dm), (0, 0, 0), "发送成功后出队");
        assert_eq!(*seen.lock().unwrap(), vec![e], "SendFn 收到完整信封");
        // 空队列 no-op
        assert_eq!(dm.tick(3000).unwrap(), TickReport::default());
    }

    #[test]
    fn unreachable_reschedules_then_retries_after_delay() {
        let calls = Arc::new(AtomicU32::new(0));
        let send: SendFn = {
            let calls = calls.clone();
            Box::new(move |_| Ok(calls.fetch_add(1, Ordering::SeqCst) >= 1))
        };
        let dm = DeliveryManager::with_policy(db(), Some(send), small_policy(), 16);
        enqueue(&dm, &env([1; 16], 1000));
        // 首拍：对方不可达 → 退避
        let r = dm.tick(1000).unwrap();
        assert_eq!((r.attempted, r.sent, r.unreachable, r.dead), (1, 0, 1, 0));
        assert_eq!(stats(&dm), (1, 0, 0), "失败不丢消息");
        // 退避窗内（delay ∈ [100, 200]）不重复投
        assert_eq!(dm.tick(1099).unwrap().attempted, 0);
        // 窗口过后自动补投成功
        let r = dm.tick(1200).unwrap();
        assert_eq!((r.attempted, r.sent), (1, 1));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(stats(&dm), (0, 0, 0));
    }

    #[test]
    fn channel_error_also_reschedules() {
        let dm = DeliveryManager::with_policy(
            db(),
            Some(Box::new(|_| Err("bt stack boom".into()))),
            small_policy(),
            16,
        );
        enqueue(&dm, &env([1; 16], 1000));
        let r = dm.tick(1000).unwrap();
        assert_eq!((r.errored, r.sent, r.dead), (1, 0, 0));
        assert_eq!(stats(&dm), (1, 0, 0), "通道错误不丢消息");
        // 退避后再次尝试
        assert_eq!(dm.tick(1000 + small_policy().max_delay_ms).unwrap().attempted, 1);
    }

    #[test]
    fn retries_exhaust_to_dead_then_revive_recovers() {
        let dm = DeliveryManager::with_policy(
            db(),
            Some(Box::new(|_| Ok(false))),
            small_policy(),
            16,
        );
        enqueue(&dm, &env([1; 16], 1000));
        // 3 次尝试（max_attempts=3）逐拍耗尽 → 死信
        let now = 1000;
        let r1 = dm.tick(now).unwrap();
        let r2 = dm.tick(now + small_policy().max_delay_ms).unwrap();
        let r3 = dm.tick(now + 2 * small_policy().max_delay_ms).unwrap();
        assert_eq!((r1.attempted, r2.attempted, r3.attempted), (1, 1, 1));
        assert_eq!((r1.dead, r2.dead), (0, 0));
        assert_eq!(r3.dead, 1, "第 3 次失败转死信");
        assert_eq!(stats(&dm), (0, 1, 0));
        // 死信不再自动投
        assert_eq!(dm.tick(now + 99 * small_policy().max_delay_ms).unwrap().attempted, 0);
        // 用户复活 → attempts 归零，恢复重试（不立即再死）
        dm.db().lock().unwrap().revive(&[1; 16]).unwrap();
        let r = dm.tick(now + 100 * small_policy().max_delay_ms).unwrap();
        assert_eq!(r.attempted, 1);
        assert_eq!(r.dead, 0, "复活后重新计入退避");
        assert_eq!(stats(&dm), (1, 0, 0));
    }

    #[test]
    fn offline_peer_keeps_message_queued_not_lost() {
        // 对方长期离线：BLE 不可达 + iroh 不可达
        let dm = DeliveryManager::with_policy(
            db(),
            Some(Box::new(|_| Ok(false))),
            RetryPolicy { max_attempts: 1000, base_delay_ms: 10, max_delay_ms: 20 },
            16,
        );
        enqueue(&dm, &env([7; 16], 1000));
        // 长时间反复 tick：退避节流，消息始终滞留队列
        let mut attempted_total = 0u32;
        for i in 0..50u64 {
            attempted_total += dm.tick(1000 + i * 20).unwrap().attempted;
        }
        assert!(attempted_total >= 1, "期间应有多次重试尝试");
        assert_eq!(stats(&dm), (1, 0, 0), "消息仍在队列，未丢");
        assert_eq!(
            dm.db().lock().unwrap().due_envelopes(u64::MAX, 10).unwrap()[0].msg_id,
            [7; 16]
        );
        // 对方上线（重绑通道）→ 下一拍送达
        dm.set_send_fn(Box::new(|_| Ok(true)));
        assert_eq!(dm.tick(3000).unwrap().sent, 1);
        assert_eq!(stats(&dm), (0, 0, 0));
    }

    #[test]
    fn no_send_fn_is_noop_then_wiring_works() {
        let dm = DeliveryManager::with_policy(db(), None, small_policy(), 16);
        enqueue(&dm, &env([1; 16], 1000));
        let r = dm.tick(5000).unwrap();
        assert_eq!(r, TickReport::default(), "通道未接：不尝试也不失败");
        assert_eq!(stats(&dm), (1, 0, 0), "消息滞留队列等待");
        dm.set_send_fn(Box::new(|_| Ok(true)));
        assert_eq!(dm.tick(5000).unwrap().sent, 1);
        dm.clear_send_fn();
        assert_eq!(dm.tick(6000).unwrap(), TickReport::default());
    }

    #[test]
    fn multiple_messages_processed_in_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let dm = {
            let order = order.clone();
            DeliveryManager::new(
                db(),
                Box::new(move |e: &Envelope| {
                    order.lock().unwrap().push(e.msg_id);
                    Ok(true)
                }),
            )
        };
        // 乱序入队，验证按创建序投递
        enqueue(&dm, &env([3; 16], 3000));
        enqueue(&dm, &env([1; 16], 1000));
        enqueue(&dm, &env([2; 16], 2000));
        let r = dm.tick(4000).unwrap();
        assert_eq!(r.sent, 3);
        assert_eq!(
            *order.lock().unwrap(),
            vec![[1u8; 16], [2; 16], [3; 16]],
            "多条消息按创建序处理"
        );
    }

    #[test]
    fn batch_limit_spreads_across_ticks() {
        let ok: SendFn = Box::new(|_| Ok(true));
        let dm = DeliveryManager::with_policy(db(), Some(ok), small_policy(), 2);
        for i in 0..5u8 {
            enqueue(&dm, &env([i; 16], 1000 + i as u64));
        }
        assert_eq!(dm.tick(5000).unwrap().attempted, 2, "单拍受批量上限约束");
        assert_eq!(dm.tick(5000).unwrap().attempted, 2);
        assert_eq!(dm.tick(5000).unwrap().attempted, 1);
        assert_eq!(stats(&dm), (0, 0, 0));
    }

    #[test]
    fn cleanup_prunes_expired_seen_and_dead() {
        let dm = DeliveryManager::with_policy(
            db(),
            Some(Box::new(|_| Ok(false))),
            RetryPolicy { max_attempts: 1, base_delay_ms: 1, max_delay_ms: 1 },
            16,
        );
        let day = 24 * 60 * 60 * 1000;
        let now = 100 * day;
        {
            let q = dm.db().lock().unwrap();
            // 去重台账：一条超 7 天窗，一条在窗内
            q.record_seen(&[1; 16], now - 8 * day).unwrap();
            q.record_seen(&[2; 16], now - day).unwrap();
            // 死信：一条超 30 天窗，一条在窗内（max_attempts=1 首败即死）
            q.enqueue_full(&env([3; 16], now - 40 * day)).unwrap();
            q.enqueue_full(&env([4; 16], now - 10 * day)).unwrap();
        }
        assert_eq!(dm.tick(now).unwrap().dead, 2);
        assert_eq!(stats(&dm), (0, 2, 2));
        let r = dm.cleanup(now).unwrap();
        assert_eq!(r.pruned_seen, 1);
        assert_eq!(r.pruned_dead, 1);
        assert_eq!(stats(&dm), (0, 1, 1), "窗内记录保留");
        // 幂等：再清一次无变化
        assert_eq!(dm.cleanup(now).unwrap(), CleanupReport::default());
    }

    #[test]
    fn legacy_enqueued_messages_still_delivered() {
        let got = Arc::new(Mutex::new(None::<Envelope>));
        let dm = {
            let got = got.clone();
            DeliveryManager::new(
                db(),
                Box::new(move |e: &Envelope| {
                    *got.lock().unwrap() = Some(e.clone());
                    Ok(true)
                }),
            )
        };
        dm.db().lock().unwrap().enqueue(&env([5; 16], 1000)).unwrap(); // 旧路径（无存档）
        let r = dm.tick(2000).unwrap();
        assert_eq!(r.sent, 1, "旧路径入队的消息同样补投（不丢）");
        let out = got.lock().unwrap().clone().unwrap();
        assert_eq!(out.msg_id, [5; 16]);
        assert_eq!(out.body, vec![1, 2, 3]);
        assert_eq!(out.sent_at_ms, 1000, "created_ms 还原为 sent_at_ms");
    }
}
