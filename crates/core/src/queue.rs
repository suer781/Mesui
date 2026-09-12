//! 加密消息队列（SQLCipher 整库加密）：待发队列 + 收件去重。
//! 通道切换零丢失的持久层基础；密钥由 Android Keystore 派生后传入。

use crate::envelope::{Envelope, MsgId};
use crate::{CoreError, Result};
use rusqlite::{params, Connection};

pub struct Db {
    conn: Connection,
}

/// 收件去重台账硬上限（红队 R2-6 修复）。与 mailbox::NonceCache 的硬顶
/// 同语义：洪泛只换来 fail-closed 拒收，不驱逐未过期的去重状态。
pub const INBOX_SEEN_CAP: u32 = 16384;

/// 去重台账保留窗（7 天，与 delivery::SEEN_RETENTION_MS 同值）。
/// 红线：必须 ≥ 最大消息投递延迟，否则旧消息可能被二次接受。
const SEEN_RETENTION_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbox (
    msg_id BLOB PRIMARY KEY,
    recipient BLOB,
    group_id BLOB,
    kind INTEGER NOT NULL,
    body BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms INTEGER NOT NULL DEFAULT 0,
    created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox_seen (
    msg_id BLOB PRIMARY KEY,
    seen_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON outbox(state, created_ms);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(state, next_attempt_ms);
CREATE TABLE IF NOT EXISTS outbox_env (
    msg_id BLOB PRIMARY KEY,
    env BLOB NOT NULL
);
";

#[derive(Debug, Clone)]
pub struct PendingRow {
    pub msg_id: MsgId,
    pub recipient: Option<[u8; 32]>,
    pub group_id: Option<[u8; 32]>,
    pub kind: u8,
    pub body: Vec<u8>,
    pub attempts: u32,
}

impl Db {
    /// 打开（或创建）加密库。`key` 为 Some 时启用 SQLCipher；
    /// key 必须是 hex/base64 等无引号字符（Kotlin 侧 Keystore 派生后 hex 编码传入）。
    pub fn open(path: &std::path::Path, key: Option<&str>) -> Result<Self> {
        // strict_crypto——文件库禁止无密钥静默明文（内存库供测试豁免）
        if key.is_none() && path != std::path::Path::new(":memory:") {
            return Err(CoreError::Db(
                "refusing to create unencrypted database: key required (strict mode)".into(),
            ));
        }
        let conn = if path == std::path::Path::new(":memory:") {
            Connection::open_in_memory()
        } else {
            Connection::open(path)
        }
        .map_err(|e| CoreError::Db(e.to_string()))?;
        if let Some(k) = key {
            let stmt = format!("PRAGMA key = '{}';", k.replace('\'', "''"));
            conn.execute_batch(&stmt).map_err(|e| CoreError::Db(e.to_string()))?;
        }
        conn.execute_batch(SCHEMA).map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(Self { conn })
    }

    /// 外部可控的 u64 时间戳入 i64 列前必须钳制——
    /// `u64::MAX as i64` 会变成 -1（排序插队/被 prune 立即清除/重放复活）。
    fn clamp_ms(v: u64) -> i64 {
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    pub fn enqueue(&self, env: &Envelope) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO outbox (msg_id, recipient, group_id, kind, body, state, attempts, created_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6)",
                params![
                    env.msg_id.as_slice(),
                    env.recipient.as_ref(),
                    env.group.as_ref(),
                    env.kind as u8 as i64,
                    env.body,
                    Self::clamp_ms(env.sent_at_ms),
                ],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn pending(&self, limit: u32) -> Result<Vec<PendingRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT msg_id, recipient, group_id, kind, body, attempts FROM outbox WHERE state='pending' ORDER BY created_ms LIMIT ?1")
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], Self::row_to_pending)
            .map_err(|e| CoreError::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|e| CoreError::Db(e.to_string()))
    }

    /// 完整信封入队（投递管理器主路径）：outbox 行 + 完整 CBOR 存档（outbox_env）。
    /// `enqueue` 的列不含 sender/ttl_hops，补投重建会缺元数据；本方法把整个
    /// 信封留档，`due_envelopes` 按 CBOR 精确还原。
    /// 红队 A4 修复：同 msg_id 重复入队**首次写入为准**（INSERT OR IGNORE）——
    /// msg_id 是线上攻击者自选的 16 字节，第二份信封的内容/收件人可以与
    /// 首份完全不同；REPLACE 会让未投递消息在投递前被偷换（且与 outbox 行
    /// 的元数据分叉）。存档与 outbox 行同进退（mark_sent / prune_dead 同步
    /// 清理），重发走 revive，不走二次入队。
    pub fn enqueue_full(&self, env: &Envelope) -> Result<()> {
        self.enqueue(env)?;
        let cbor = env.to_cbor()?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO outbox_env (msg_id, env) VALUES (?1, ?2)",
                params![env.msg_id.as_slice(), cbor],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn mark_sent(&self, msg_id: &MsgId) -> Result<()> {
        self.conn
            .execute("UPDATE outbox SET state='sent' WHERE msg_id=?1", params![msg_id.as_slice()])
            .map_err(|e| CoreError::Db(e.to_string()))?;
        // 红队 P2 修复：同步清理 outbox_env 存档（防孤儿行无限增长）
        self.conn
            .execute("DELETE FROM outbox_env WHERE msg_id=?1", params![msg_id.as_slice()])
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// 重试调度：递增尝试计数并设定下次尝试时间；超过策略上限转死信。
    /// 返回 true = 已转死信（调用方应停止重试并提示用户）。
    pub fn fail_and_reschedule(
        &self,
        msg_id: &MsgId,
        policy: &crate::retry::RetryPolicy,
        now_ms: u64,
    ) -> Result<bool> {
        let attempts: i64 = self
            .conn
            .query_row(
                "SELECT attempts FROM outbox WHERE msg_id=?1",
                params![msg_id.as_slice()],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let attempts = attempts as u32 + 1;
        if policy.exhausted(attempts) {
            self.conn
                .execute(
                    "UPDATE outbox SET state='dead', attempts=?2 WHERE msg_id=?1",
                    params![msg_id.as_slice(), attempts as i64],
                )
                .map_err(|e| CoreError::Db(e.to_string()))?;
            return Ok(true);
        }
        let delay = policy.next_delay_ms(attempts)?;
        // now_ms + delay 在 u64 域饱和，再钳制进 i64 列
        let next_attempt = Self::clamp_ms(now_ms.saturating_add(delay));
        self.conn
            .execute(
                "UPDATE outbox SET attempts=?2, next_attempt_ms=?3 WHERE msg_id=?1",
                params![msg_id.as_slice(), attempts as i64, next_attempt],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(false)
    }

    /// 到期可投递的消息（pending 且下次尝试时间已到，按创建序）。
    /// 驱动方（通道状态机）周期性调用；未到期的不返回。
    pub fn due(&self, now_ms: u64, limit: u32) -> Result<Vec<PendingRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT msg_id, recipient, group_id, kind, body, attempts FROM outbox
                 WHERE state='pending' AND next_attempt_ms <= ?1 ORDER BY created_ms LIMIT ?2",
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params![Self::clamp_ms(now_ms), limit], |r| {
                Self::row_to_pending(r)
            })
            .map_err(|e| CoreError::Db(e.to_string()))?;
            rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|e| CoreError::Db(e.to_string()))
    }

    /// 到期消息的完整信封重建（delivery.rs tick 的取件口）：
    /// 与 `due` 同一判定（pending 且 next_attempt_ms 已到，按创建序），
    /// 优先读 outbox_env 的 CBOR 存档无损还原；旧 `enqueue` 行按 outbox
    /// 字段尽力重建（sender 缺失置零、ttl_hops 取默认——消息不丢优先于
    /// 元数据完整）。行被篡改/损坏时报错，不静默投出畸形信封。
    pub fn due_envelopes(&self, now_ms: u64, limit: u32) -> Result<Vec<Envelope>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT o.msg_id, o.recipient, o.group_id, o.kind, o.body, o.created_ms, e.env
                 FROM outbox o LEFT JOIN outbox_env e ON o.msg_id = e.msg_id
                 WHERE o.state='pending' AND o.next_attempt_ms <= ?1
                 ORDER BY o.created_ms LIMIT ?2",
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params![Self::clamp_ms(now_ms), limit], |r| {
                let env_blob: Option<Vec<u8>> = r.get(6)?;
                if let Some(bytes) = env_blob {
                    return Envelope::from_cbor(&bytes).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Blob,
                            Box::new(e),
                        )
                    });
                }
                let msg_id_raw: Vec<u8> = r.get(0)?;
                let msg_id: MsgId = msg_id_raw.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(0, "msg_id".into(), rusqlite::types::Type::Blob)
                })?;
                let recipient: Option<Vec<u8>> = r.get(1)?;
                let recipient = match recipient {
                    Some(v) => Some(v.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(1, "recipient".into(), rusqlite::types::Type::Blob)
                    })?),
                    None => None,
                };
                let group: Option<Vec<u8>> = r.get(2)?;
                let group = match group {
                    Some(v) => Some(v.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(2, "group_id".into(), rusqlite::types::Type::Blob)
                    })?),
                    None => None,
                };
                let kind: i64 = r.get(3)?;
                let kind = match kind {
                    1 => crate::envelope::PayloadKind::Text,
                    2 => crate::envelope::PayloadKind::SessionMgmt,
                    3 => crate::envelope::PayloadKind::GroupMgmt,
                    4 => crate::envelope::PayloadKind::NodeCtl,
                    other => {
                        return Err(rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Integer,
                            Box::new(CoreError::Db(format!("未知 PayloadKind: {other}"))),
                        ))
                    }
                };
                let body: Vec<u8> = r.get(4)?;
                let created_ms: i64 = r.get(5)?;
                Ok(Envelope {
                    msg_id,
                    sender: [0u8; 32], // 旧路径未存发送方：置零占位
                    recipient,
                    group,
                    kind,
                    body,
                    sent_at_ms: created_ms.max(0) as u64,
                    ttl_hops: 6,
                })
            })
            .map_err(|e| CoreError::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|e| CoreError::Db(e.to_string()))
    }

    /// 重新入队死信（用户手动「再试一次」时）。
    /// 红队 R2-5 修复：加 state='dead' 守卫——**只有死信可复活**。此前对任意
    /// msg_id 生效：把已送达（sent）行的 id 传进来（死信 UI id 混用 / 上层 bug /
    /// 未来批处理）会把已送达消息复活成 pending → 二次投递。守卫后非 dead 行
    /// 一律 no-op。
    pub fn revive(&self, msg_id: &MsgId) -> Result<()> {
        self.conn
            .execute(
                "UPDATE outbox SET state='pending', attempts=0, next_attempt_ms=0
                 WHERE msg_id=?1 AND state='dead'",
                params![msg_id.as_slice()],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// 行转换共享实现：数据库行若被篡改/损坏，报错而非静默填零投递。
    fn row_to_pending(r: &rusqlite::Row) -> rusqlite::Result<PendingRow> {
        let msg_id_raw: Vec<u8> = r.get(0)?;
        let msg_id: MsgId = msg_id_raw.try_into().map_err(|_| {
            rusqlite::Error::InvalidColumnType(0, "msg_id".into(), rusqlite::types::Type::Blob)
        })?;
        let recipient: Option<Vec<u8>> = r.get(1)?;
        let recipient = match recipient {
            Some(v) => Some(v.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(1, "recipient".into(), rusqlite::types::Type::Blob)
            })?),
            None => None,
        };
        let group_id: Option<Vec<u8>> = r.get(2)?;
        let group_id = match group_id {
            Some(v) => Some(v.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(2, "group_id".into(), rusqlite::types::Type::Blob)
            })?),
            None => None,
        };
        let kind: i64 = r.get(3)?;
        let body: Vec<u8> = r.get(4)?;
        let attempts: i64 = r.get(5)?;
        Ok(PendingRow {
            msg_id,
            recipient,
            group_id,
            kind: kind as u8,
            body,
            attempts: attempts as u32,
        })
    }

    /// 收件去重：返回 true = 首次见到（应投递），false = 重复（静默丢弃）。
    /// now_ms 钳制进 i64 正数域——u64::MAX 入库会变 -1，
    /// 随后的 prune_seen(0) 立即删除该记录，构成「重放复活」链。
    ///
    /// 红队 R2-6 修复：台账硬上限 [`INBOX_SEEN_CAP`]。msg_id 是线上攻击者
    /// 自选字段（信封外层明文），无上限 = 任何能投递信封的路径灌 N 条异
    /// msg_id 即 N 行持久化记录、7 天保留窗内只增不减（磁盘版洪泛）。
    /// 语义与 mailbox::NonceCache 对齐：满员先补裁剪窗外记录（保留窗 = 7 天，
    /// 必须 ≥ 最大投递延迟），仍满则拒收新记录（fail-closed）——洪泛只换来
    /// 拒收，绝不驱逐未过期的去重状态（重放防线完整）。
    pub fn record_seen(&self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM inbox_seen", [], |r| r.get(0))
            .map_err(|e| CoreError::Db(e.to_string()))?;
        if count >= INBOX_SEEN_CAP as i64 {
            // 补裁剪：窗外记录（seen_ms < now-7天）本就该被例行清理清掉，
            // 这里在容量压力下提前触发（prune_seen 只按时间不按容量）
            let cutoff = Self::clamp_ms(now_ms.saturating_sub(SEEN_RETENTION_WINDOW_MS));
            self.conn
                .execute("DELETE FROM inbox_seen WHERE seen_ms < ?1", params![cutoff])
                .map_err(|e| CoreError::Db(e.to_string()))?;
            let left: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM inbox_seen", [], |r| r.get(0))
                .map_err(|e| CoreError::Db(e.to_string()))?;
            if left >= INBOX_SEEN_CAP as i64 {
                return Ok(false); // fail-closed：满员拒新，不驱逐窗内去重状态
            }
        }
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO inbox_seen (msg_id, seen_ms) VALUES (?1, ?2)",
                params![msg_id.as_slice(), Self::clamp_ms(now_ms)],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(n == 1)
    }

    /// 裁剪过期去重记录（保留窗口必须 ≥ 最大消息投递延迟，
    /// 否则旧消息可能被二次接受——调用方窗口不得小于 7 天）。
    pub fn prune_seen(&self, before_ms: u64) -> Result<usize> {
        let n = self
            .conn
            .execute("DELETE FROM inbox_seen WHERE seen_ms < ?1", params![Self::clamp_ms(before_ms)])
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(n)
    }

    /// 清理过期死信（仅删 state='dead' 且创建时间早于 cutoff 的行）。
    /// 库未记录死亡时刻，以入队时间（created_ms）做保守近似——
    /// 保留窗内用户随时可 revive，过后由 delivery::cleanup 清除。
    pub fn prune_dead(&self, created_before_ms: u64) -> Result<usize> {
        let n = self
            .conn
            .execute(
                "DELETE FROM outbox WHERE state='dead' AND created_ms < ?1",
                params![Self::clamp_ms(created_before_ms)],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        // 红队 P2 修复：同步清理对应的 outbox_env 存档（防孤儿行）
        self.conn
            .execute(
                "DELETE FROM outbox_env WHERE msg_id NOT IN (SELECT msg_id FROM outbox)",
                [],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(n)
    }

    /// 清理已发送行（红队 R2-5 修复：sent 行连密文此前永久堆积——存储无界
    /// 增长）。仅删 state='sent' 且创建时间早于 cutoff 的行（死信不受影响，
    /// 其清理走 prune_dead 的 30 天窗）；outbox_env 孤儿同步清理。
    /// cutoff 由调用方按保留窗计算（delivery::SENT_RETENTION_MS = 7 天，
    /// 给「已送达」的 UI 状态留展示期）。
    pub fn prune_sent(&self, created_before_ms: u64) -> Result<usize> {
        let n = self
            .conn
            .execute(
                "DELETE FROM outbox WHERE state='sent' AND created_ms < ?1",
                params![Self::clamp_ms(created_before_ms)],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        self.conn
            .execute(
                "DELETE FROM outbox_env WHERE msg_id NOT IN (SELECT msg_id FROM outbox)",
                [],
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(n)
    }

    /// 死信清单（UI「发送失败，点按重试」用，按创建序）。
    pub fn dead_list(&self, limit: u32) -> Result<Vec<MsgId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT msg_id FROM outbox WHERE state='dead' ORDER BY created_ms LIMIT ?1")
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                let raw: Vec<u8> = r.get(0)?;
                raw.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(0, "msg_id".into(), rusqlite::types::Type::Blob)
                })
            })
            .map_err(|e| CoreError::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|e| CoreError::Db(e.to_string()))
    }

    /// (待发, 死信, 已见去重) 计数。
    pub fn stats(&self) -> Result<(u32, u32, u32)> {
        let pending: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM outbox WHERE state='pending'", [], |r| r.get(0))
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let dead: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM outbox WHERE state='dead'", [], |r| r.get(0))
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let seen: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM inbox_seen", [], |r| r.get(0))
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok((pending as u32, dead as u32, seen as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, NodeId};
    use crate::envelope::PayloadKind;

    fn env(msg_id: MsgId, recipient: Option<NodeId>) -> Envelope {
        let id = Identity::generate().unwrap();
        Envelope {
            msg_id,
            sender: id.node_id(),
            recipient,
            group: None,
            kind: PayloadKind::Text,
            body: vec![1, 2, 3],
            sent_at_ms: 1000,
            ttl_hops: 6,
        }
    }

    #[test]
    fn enqueue_pending_mark_sent() {
        let db = Db::open(std::path::Path::new(":memory:"), Some("test1234")).unwrap();
        let e1 = env([1; 16], Some([5; 32]));
        let e2 = env([2; 16], None);
        db.enqueue(&e1).unwrap();
        db.enqueue(&e2).unwrap();
        // 同 ID 重复入队被忽略
        db.enqueue(&e1).unwrap();
        assert_eq!(db.pending(10).unwrap().len(), 2);
        db.mark_sent(&[1; 16]).unwrap();
        let left = db.pending(10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].msg_id, [2; 16]);
        assert_eq!(db.stats().unwrap(), (1, 0, 0));
    }

    #[test]
    fn dedup_persists() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        assert!(db.record_seen(&[9; 16], 111).unwrap());
        assert!(!db.record_seen(&[9; 16], 222).unwrap());
        assert_eq!(db.stats().unwrap().2, 1);
    }

    #[test]
    fn order_by_created() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        let mut late = env([1; 16], None);
        late.sent_at_ms = 5000;
        let mut early = env([2; 16], None);
        early.sent_at_ms = 1000;
        db.enqueue(&late).unwrap();
        db.enqueue(&early).unwrap();
        let rows = db.pending(2).unwrap();
        assert_eq!(rows[0].msg_id, [2; 16], "早的先发");
    }

    #[test]
    fn retry_schedule_due_dead_and_revive() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        let policy = crate::retry::RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 100,
            max_delay_ms: 400,
        };
        db.enqueue(&env([1; 16], None)).unwrap();
        // 未失败过：立即到期可投
        assert_eq!(db.due(1000, 10).unwrap().len(), 1);
        // 第一次失败 → 下次尝试被推迟（delay ∈ [100,200]）
        assert!(!db.fail_and_reschedule(&[1; 16], &policy, 1000).unwrap());
        assert!(db.due(1000, 10).unwrap().is_empty(), "推迟期内不应到期");
        assert_eq!(db.due(2000, 10).unwrap().len(), 1, "推迟期后恢复到期");
        // 第二次失败仍不死
        assert!(!db.fail_and_reschedule(&[1; 16], &policy, 2000).unwrap());
        // 第三次失败（attempts==max）→ 死信
        assert!(db.fail_and_reschedule(&[1; 16], &policy, 3000).unwrap());
        assert_eq!(db.due(99_999, 10).unwrap().len(), 0);
        assert_eq!(db.stats().unwrap(), (0, 1, 0));
        // 用户手动复活 → 重新到期
        db.revive(&[1; 16]).unwrap();
        assert_eq!(db.due(99_999, 10).unwrap().len(), 1);
        assert_eq!(db.stats().unwrap(), (1, 0, 0));
    }

    // ══════════ 投递接线新增方法（delivery.rs 依赖） ══════════

    #[test]
    fn enqueue_full_and_due_envelopes_roundtrip() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        let mut e = env([7; 16], Some([5; 32]));
        e.sender = Identity::generate().unwrap().node_id();
        e.sent_at_ms = 42_000;
        e.ttl_hops = 3;
        e.body = vec![9, 9, 9, 9];
        db.enqueue_full(&e).unwrap();
        let got = db.due_envelopes(43_000, 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], e, "完整信封必须无损还原（sender/ttl_hops/时间）");
    }

    #[test]
    fn due_envelopes_falls_back_for_legacy_rows() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        db.enqueue(&env([3; 16], None)).unwrap(); // 旧路径：无 CBOR 存档
        let got = db.due_envelopes(10_000, 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_id, [3; 16]);
        assert_eq!(got[0].body, vec![1, 2, 3]);
        assert_eq!(got[0].sent_at_ms, 1000, "created_ms 还原为 sent_at_ms");
    }

    #[test]
    fn prune_dead_and_dead_list() {
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        let policy = crate::retry::RetryPolicy { max_attempts: 1, base_delay_ms: 1, max_delay_ms: 1 };
        db.enqueue(&env([1; 16], None)).unwrap();
        db.enqueue(&env([2; 16], None)).unwrap();
        db.fail_and_reschedule(&[1; 16], &policy, 1000).unwrap(); // 首败即死
        db.fail_and_reschedule(&[2; 16], &policy, 1000).unwrap();
        assert_eq!(db.dead_list(10).unwrap().len(), 2);
        // cutoff 边界：created_ms == 1000 不在 < 1000 内 → 全保留
        assert_eq!(db.prune_dead(1000).unwrap(), 0);
        assert_eq!(db.dead_list(10).unwrap().len(), 2);
        // 复活一条 → 死信清单只剩另一条；过 cutoff 的死信被清
        db.revive(&[1; 16]).unwrap();
        assert_eq!(db.dead_list(10).unwrap(), vec![[2u8; 16]]);
        assert_eq!(db.prune_dead(5000).unwrap(), 1);
        assert!(db.dead_list(10).unwrap().is_empty());
        assert_eq!(db.stats().unwrap(), (1, 0, 0), "复活的那条仍是 pending");
    }

    #[test]
    fn enqueue_full_same_msg_id_first_write_wins() {
        // 红队 A4 修复回归：msg_id 是线上攻击者自选的 16 字节——
        // 同 id 二次入队（内容/收件人完全不同）不得偷换已入队消息
        let db = Db::open(std::path::Path::new(":memory:"), None).unwrap();
        let bob = [0xB0; 32];
        let mallory = [0xE5; 32];
        let x = [0x42; 16];
        let first = Envelope {
            msg_id: x, sender: [1; 32], recipient: Some(bob), group: None,
            kind: PayloadKind::Text, body: vec![1], sent_at_ms: 1000, ttl_hops: 6,
        };
        let second = Envelope {
            msg_id: x, sender: [2; 32], recipient: Some(mallory), group: None,
            kind: PayloadKind::Text, body: vec![2, 2, 2], sent_at_ms: 2000, ttl_hops: 6,
        };
        db.enqueue_full(&first).unwrap();
        db.enqueue_full(&second).unwrap();
        assert_eq!(db.pending(10).unwrap().len(), 1, "outbox 行幂等");
        let due = db.due_envelopes(5000, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].body, vec![1], "RED: 存档被 REPLACE 偷换（首次写入必须为准）");
        assert_eq!(due[0].sender, [1; 32], "RED: sender 被二次入队偷换");
        assert_eq!(due[0].recipient, Some(bob), "RED: 收件人被二次入队偷换");
        assert_eq!(due[0].sent_at_ms, 1000, "RED: 时间戳被二次入队偷换");
        // 与 outbox 行不再分叉：CBOR 存档 = 首份信封的无损还原
        assert_eq!(due[0], first);
    }
}
