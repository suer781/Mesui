//! 联系人与聊天记录（阶段 3）：SQLCipher 加密库落盘。
//!
//! 与 Signal store 可指向同一库文件（不同表、不同连接）：SQLCipher 库级
//! 加密下，聊天记录以明文列存储由整库加密覆盖；两个连接的写冲突靠
//! `busy_timeout` 串行化。联系人存对方长期身份公钥（SAS 校验状态决定
//! verified），重连免扫码靠 Signal store 的 TOFU pin，两者名字（地址）对齐。

use crate::{CoreError, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 联系人（字段对齐 wiki 阶段 3 任务 4：身份公钥、备注、SAS 校验状态、桶地址）。
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub name: String,
    pub identity: Vec<u8>,
    pub bucket: Vec<u8>,
    pub verified: bool,
    pub note: String,
    pub added_ms: i64,
}

/// 一条聊天记录（显示用；传输重试是 queue.rs 的职责，不在此混用）。
#[derive(Debug, Clone)]
pub struct ChatMsg {
    pub peer: String,
    pub outgoing: bool,
    pub text: String,
    pub ts_ms: i64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS contacts (
    name TEXT PRIMARY KEY,
    identity BLOB NOT NULL,
    bucket BLOB NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    added_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer TEXT NOT NULL,
    outgoing INTEGER NOT NULL,
    text TEXT NOT NULL,
    ts_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_peer_ts ON chat_log(peer, ts_ms);
";

pub struct ContactStore {
    conn: Mutex<Connection>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl ContactStore {
    /// 打开（或创建）加密库。strict 约定与 queue::Db / signal_store 相同：
    /// 文件库必须给 key，内存库豁免（供测试）。
    pub fn open(path: &std::path::Path, key: Option<&str>) -> Result<Self> {
        if key.is_none() && path != std::path::Path::new(":memory:") {
            return Err(CoreError::Db(
                "refusing to create unencrypted contact store: key required (strict mode)".into(),
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
        // 与 Signal store 同文件双连接：写锁竞争等 5 秒再报错
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute_batch(SCHEMA).map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// 新增或整体覆盖一个联系人（重新扫码加好友即覆盖）。
    pub fn upsert(
        &self,
        name: &str,
        identity: &[u8],
        bucket: &[u8],
        verified: bool,
        note: &str,
    ) -> Result<()> {
        if identity.len() != 32 {
            return Err(CoreError::Config("contact identity must be 32 bytes".into()));
        }
        if bucket.len() != 32 {
            return Err(CoreError::Config("contact bucket must be 32 bytes".into()));
        }
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute(
            "INSERT INTO contacts (name, identity, bucket, verified, note, added_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
               identity=?2, bucket=?3, verified=?4, note=?5",
            params![name, identity, bucket, verified as i64, note, now_ms()],
        )
        .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ContactInfo>> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT name, identity, bucket, verified, note, added_ms FROM contacts ORDER BY added_ms")
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ContactInfo {
                    name: r.get(0)?,
                    identity: r.get(1)?,
                    bucket: r.get(2)?,
                    verified: r.get::<_, i64>(3)? != 0,
                    note: r.get(4)?,
                    added_ms: r.get(5)?,
                })
            })
            .map_err(|e| CoreError::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Db(e.to_string()))
    }

    /// SAS 比对确认后标记（wiki 流程：比对通过才 verified=true + TOFU pin）。
    pub fn set_verified(&self, name: &str, verified: bool) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute(
            "UPDATE contacts SET verified=?2 WHERE name=?1",
            params![name, verified as i64],
        )
        .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute("DELETE FROM contacts WHERE name=?1", params![name])
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn append_message(&self, peer: &str, outgoing: bool, text: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute(
            "INSERT INTO chat_log (peer, outgoing, text, ts_ms) VALUES (?1, ?2, ?3, ?4)",
            params![peer, outgoing as i64, text, now_ms()],
        )
        .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// 最近 limit 条，按时间升序返回（UI 直接渲染）。
    pub fn messages(&self, peer: &str, limit: i32) -> Result<Vec<ChatMsg>> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT peer, outgoing, text, ts_ms FROM (
                   SELECT id, peer, outgoing, text, ts_ms FROM chat_log
                   WHERE peer=?1 ORDER BY ts_ms DESC, id DESC LIMIT ?2
                 ) ORDER BY ts_ms ASC, id ASC",
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params![peer, limit], |r| {
                Ok(ChatMsg {
                    peer: r.get(0)?,
                    outgoing: r.get::<_, i64>(1)? != 0,
                    text: r.get(2)?,
                    ts_ms: r.get(3)?,
                })
            })
            .map_err(|e| CoreError::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Db(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("dc-contacts-{}-{}.db", tag, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn upsert_list_verify_delete() {
        let s = ContactStore::open(std::path::Path::new(":memory:"), None).unwrap();
        s.upsert("bob", &[1u8; 32], &[2u8; 32], false, "").unwrap();
        s.upsert("alice", &[3u8; 32], &[4u8; 32], true, "备注").unwrap();
        let all = s.list().unwrap();
        assert_eq!(all.len(), 2);
        // 重新加好友：同名覆盖不重复
        s.upsert("bob", &[5u8; 32], &[6u8; 32], true, "").unwrap();
        assert_eq!(s.list().unwrap().len(), 2);
        let bob = s.list().unwrap().into_iter().find(|c| c.name == "bob").unwrap();
        assert_eq!(bob.identity, vec![5u8; 32]);
        assert!(bob.verified);
        s.delete("alice").unwrap();
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn rejects_wrong_sizes() {
        let s = ContactStore::open(std::path::Path::new(":memory:"), None).unwrap();
        assert!(s.upsert("x", &[0u8; 31], &[0u8; 32], false, "").is_err());
        assert!(s.upsert("x", &[0u8; 32], &[0u8; 33], false, "").is_err());
    }

    #[test]
    fn contacts_and_chat_persist_reopen() {
        let path = temp_db("reopen");
        {
            let s = ContactStore::open(&path, Some("kk")).unwrap();
            s.upsert("bob", &[7u8; 32], &[8u8; 32], true, "").unwrap();
            s.append_message("bob", true, "hi").unwrap();
            s.append_message("bob", false, "yo").unwrap();
        }
        let s = ContactStore::open(&path, Some("kk")).unwrap();
        assert_eq!(s.list().unwrap().len(), 1);
        let msgs = s.messages("bob", 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].text, "hi"); // 时间升序
        assert_eq!(msgs[1].text, "yo");
        assert!(msgs[0].outgoing && !msgs[1].outgoing);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_store_requires_key() {
        let path = temp_db("nokey");
        assert!(ContactStore::open(&path, None).is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// 错误 key 打开已有库必须失败（不是静默空库）——联系人表同理受整库加密保护。
    #[test]
    fn wrong_key_rejected() {
        let path = temp_db("wrongkey");
        {
            let s = ContactStore::open(&path, Some("right")).unwrap();
            s.upsert("bob", &[1u8; 32], &[2u8; 32], false, "").unwrap();
        }
        assert!(ContactStore::open(&path, Some("wrong")).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
