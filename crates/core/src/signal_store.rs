//! SQLCipher 持久化 Signal store（阶段 3）：libsignal 五个 store trait 全部落库。
//!
//! 设计要点：
//! - `message_decrypt` 等入口要同时传 5 个 `&mut dyn XxxStore`，单一对象无法
//!   同时以多个 `&mut` 借出 → 连接包 `Arc<Mutex<Connection>>`，store 本体
//!   廉价 `Clone`，调用点克隆五份传入（共享同一连接，锁内串行）。
//! - trait 方法体是同步代码（无 await 持锁），由 handshake.rs 的 `block_on`
//!   在当前线程驱动，`std::sync::Mutex` 即可；不会跨 await 持锁。
//! - TOFU 语义与 libsignal InMem 实现一致：无记录=信任（首次），
//!   有记录且同钥=信任，有记录且异钥=拒绝。
//! - Kyber 预密钥按一次性语义处理：`mark_kyber_pre_key_used` 即删除
//!   （本项目每次出示 QR 都新生成一组预密钥，不存在 last-resort 复用）。

use crate::{CoreError, Result};
use async_trait::async_trait;
use libsignal_protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, SessionRecord, SessionStore, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

/// 数据库错误 → libsignal 错误（trait 面必须返回 SignalProtocolError）。
/// 用 InvalidState 承载：ApplicationCallbackError 要求 UnwindSafe，
/// rusqlite::Error 内含 Box<dyn Error> 不保证满足。
fn db_sig_err(method: &'static str, e: rusqlite::Error) -> libsignal_protocol::SignalProtocolError {
    libsignal_protocol::SignalProtocolError::InvalidState(method, format!("{e:?}"))
}

fn lock_err(method: &'static str) -> libsignal_protocol::SignalProtocolError {
    libsignal_protocol::SignalProtocolError::InvalidState(method, "signal store mutex poisoned".into())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS local_identity (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    identity_pair BLOB NOT NULL,
    registration_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_identities (
    name TEXT NOT NULL,
    device INTEGER NOT NULL,
    identity BLOB NOT NULL,
    PRIMARY KEY (name, device)
);
CREATE TABLE IF NOT EXISTS sessions (
    name TEXT NOT NULL,
    device INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (name, device)
);
CREATE TABLE IF NOT EXISTS pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
";

/// SQLCipher 后端的 Signal 五联 store。`Clone` 廉价（Arc 计数），
/// 克隆体共享同一连接——见模块注释里 `&mut dyn` 多路传入的设计说明。
#[derive(Clone)]
pub struct SqlSignalStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqlSignalStore {
    /// 打开（或创建）加密库。`key` 为 Some 时启用 SQLCipher；
    /// 与 queue::Db 同一约定：文件库必须给 key（strict 模式），内存库豁免。
    pub fn open(path: &std::path::Path, key: Option<&str>) -> Result<Self> {
        if key.is_none() && path != std::path::Path::new(":memory:") {
            return Err(CoreError::Db(
                "refusing to create unencrypted signal store: key required (strict mode)".into(),
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
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn with_conn<T>(&self, method: &'static str, f: impl FnOnce(&Connection) -> std::result::Result<T, rusqlite::Error>) -> std::result::Result<T, libsignal_protocol::SignalProtocolError> {
        let conn = self.conn.lock().map_err(|_| lock_err(method))?;
        f(&conn).map_err(|e| db_sig_err(method, e))
    }

    // ---------- 非 trait 的本地身份引导（Device::open 用） ----------

    /// 本地身份对（含私钥）与 registration_id；尚未引导时为 None。
    pub fn local_identity(&self) -> Result<Option<(Vec<u8>, u32)>> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        let row = conn
            .query_row(
                "SELECT identity_pair, registration_id FROM local_identity WHERE id = 0",
                [],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(row.map(|(pair, reg)| (pair, reg as u32)))
    }

    /// 写入本地身份（仅首启调用一次）。
    pub fn save_local_identity(&self, pair: &[u8], registration_id: u32) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO local_identity (id, identity_pair, registration_id) VALUES (0, ?1, ?2)",
            params![pair, registration_id as i64],
        )
        .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// 预密钥单调 id：每次出示 QR 生成新组，避免固定 id=1 覆盖上一组
    /// （两组同时悬而未决时，前一组扫码方的消息会解不开）。
    pub fn next_prekey_id(&self, table: &str) -> Result<u32> {
        let table = match table {
            "pre_keys" | "signed_pre_keys" | "kyber_pre_keys" => table,
            _ => return Err(CoreError::Config("unknown prekey table".into())),
        };
        let conn = self.conn.lock().map_err(|e| CoreError::Db(e.to_string()))?;
        let next: i64 = conn
            .query_row(
                &format!("SELECT COALESCE(MAX(id), 0) + 1 FROM {table}"),
                [],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::Db(e.to_string()))?;
        Ok(u32::try_from(next).unwrap_or(1))
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqlSignalStore {
    async fn get_identity_key_pair(&self) -> libsignal_protocol::Result<IdentityKeyPair> {
        let row = self.with_conn("get_identity_key_pair", |c| {
            c.query_row(
                "SELECT identity_pair FROM local_identity WHERE id = 0",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
        })?;
        IdentityKeyPair::try_from(row.as_slice())
    }

    async fn get_local_registration_id(&self) -> libsignal_protocol::Result<u32> {
        self.with_conn("get_local_registration_id", |c| {
            c.query_row(
                "SELECT registration_id FROM local_identity WHERE id = 0",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|r| r as u32)
        })
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> libsignal_protocol::Result<IdentityChange> {
        let existing: Option<Vec<u8>> = self.with_conn("save_identity", |c| {
            c.query_row(
                "SELECT identity FROM trusted_identities WHERE name = ?1 AND device = ?2",
                params![address.name(), u8::from(address.device_id()) as i64],
                |r| r.get(0),
            )
            .optional()
        })?;
        let changed = match existing {
            Some(prev) => IdentityKey::try_from(prev.as_slice())? != *identity,
            None => false,
        };
        self.with_conn("save_identity", |c| {
            c.execute(
                "INSERT OR REPLACE INTO trusted_identities (name, device, identity) VALUES (?1, ?2, ?3)",
                params![address.name(), u8::from(address.device_id()) as i64, identity.serialize().to_vec()],
            )
        })?;
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> libsignal_protocol::Result<bool> {
        let existing: Option<Vec<u8>> = self.with_conn("is_trusted_identity", |c| {
            c.query_row(
                "SELECT identity FROM trusted_identities WHERE name = ?1 AND device = ?2",
                params![address.name(), u8::from(address.device_id()) as i64],
                |r| r.get(0),
            )
            .optional()
        })?;
        Ok(match existing {
            None => true, // TOFU 首次使用
            Some(prev) => IdentityKey::try_from(prev.as_slice())? == *identity,
        })
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<IdentityKey>> {
        let existing: Option<Vec<u8>> = self.with_conn("get_identity", |c| {
            c.query_row(
                "SELECT identity FROM trusted_identities WHERE name = ?1 AND device = ?2",
                params![address.name(), u8::from(address.device_id()) as i64],
                |r| r.get(0),
            )
            .optional()
        })?;
        match existing {
            None => Ok(None),
            Some(b) => Ok(Some(IdentityKey::try_from(b.as_slice())?)),
        }
    }
}

#[async_trait(?Send)]
impl SessionStore for SqlSignalStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<SessionRecord>> {
        let row: Option<Vec<u8>> = self.with_conn("load_session", |c| {
            c.query_row(
                "SELECT record FROM sessions WHERE name = ?1 AND device = ?2",
                params![address.name(), u8::from(address.device_id()) as i64],
                |r| r.get(0),
            )
            .optional()
        })?;
        match row {
            None => Ok(None),
            Some(b) => Ok(Some(SessionRecord::deserialize(&b)?)),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> libsignal_protocol::Result<()> {
        let bytes = record.serialize()?;
        self.with_conn("store_session", |c| {
            c.execute(
                "INSERT OR REPLACE INTO sessions (name, device, record) VALUES (?1, ?2, ?3)",
                params![address.name(), u8::from(address.device_id()) as i64, bytes],
            )
        })?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqlSignalStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> libsignal_protocol::Result<PreKeyRecord> {
        let bytes: Vec<u8> = self.with_conn("get_pre_key", |c| {
            c.query_row(
                "SELECT record FROM pre_keys WHERE id = ?1",
                params![u32::from(prekey_id) as i64],
                |r| r.get(0),
            )
        })?;
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        let bytes = record.serialize()?;
        self.with_conn("save_pre_key", |c| {
            c.execute(
                "INSERT OR REPLACE INTO pre_keys (id, record) VALUES (?1, ?2)",
                params![u32::from(prekey_id) as i64, bytes],
            )
        })?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> libsignal_protocol::Result<()> {
        self.with_conn("remove_pre_key", |c| {
            c.execute(
                "DELETE FROM pre_keys WHERE id = ?1",
                params![u32::from(prekey_id) as i64],
            )
        })?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqlSignalStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> libsignal_protocol::Result<SignedPreKeyRecord> {
        let bytes: Vec<u8> = self.with_conn("get_signed_pre_key", |c| {
            c.query_row(
                "SELECT record FROM signed_pre_keys WHERE id = ?1",
                params![u32::from(signed_prekey_id) as i64],
                |r| r.get(0),
            )
        })?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        let bytes = record.serialize()?;
        self.with_conn("save_signed_pre_key", |c| {
            c.execute(
                "INSERT OR REPLACE INTO signed_pre_keys (id, record) VALUES (?1, ?2)",
                params![u32::from(signed_prekey_id) as i64, bytes],
            )
        })?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqlSignalStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> libsignal_protocol::Result<KyberPreKeyRecord> {
        let bytes: Vec<u8> = self.with_conn("get_kyber_pre_key", |c| {
            c.query_row(
                "SELECT record FROM kyber_pre_keys WHERE id = ?1",
                params![u32::from(kyber_prekey_id) as i64],
                |r| r.get(0),
            )
        })?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        let bytes = record.serialize()?;
        self.with_conn("save_kyber_pre_key", |c| {
            c.execute(
                "INSERT OR REPLACE INTO kyber_pre_keys (id, record) VALUES (?1, ?2)",
                params![u32::from(kyber_prekey_id) as i64, bytes],
            )
        })?;
        Ok(())
    }

    /// 一次性语义：直接删除（本项目每次出示 QR 生成全新组，无 last-resort 复用）。
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &libsignal_protocol::PublicKey,
    ) -> libsignal_protocol::Result<()> {
        self.with_conn("mark_kyber_pre_key_used", |c| {
            c.execute(
                "DELETE FROM kyber_pre_keys WHERE id = ?1",
                params![u32::from(kyber_prekey_id) as i64],
            )
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Device;

    fn temp_db(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "dc-signal-store-{}-{}.db",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// 首启生成的身份在重开后保持同一把（TOFU 信任根不能漂移）。
    #[test]
    fn identity_key_stable_across_reopen() {
        let path = temp_db("stable");
        let k1 = {
            let alice = Device::open(&path, Some("testkey"), "alice").unwrap();
            alice.identity_key().unwrap()
        };
        let k2 = {
            let alice = Device::open(&path, Some("testkey"), "alice").unwrap();
            alice.identity_key().unwrap()
        };
        assert_eq!(k1.serialize(), k2.serialize(), "重开后长期身份必须不变");
        let _ = std::fs::remove_file(&path);
    }

    /// TOFU pin 持久化：pin 过的对方身份，重开后仍可信；换钥仍拒绝。
    #[test]
    fn tofu_pin_persists() {
        let path = temp_db("tofu");
        let bob = Device::generate("bob").unwrap();
        let bob_addr = bob.address().clone();
        let bik = bob.identity_key().unwrap();
        {
            let mut alice = Device::open(&path, Some("testkey"), "alice").unwrap();
            assert!(alice.is_trusted(&bob_addr, &bik).unwrap());
            alice.pin_identity(&bob_addr, &bik).unwrap();
        }
        {
            let mut alice = Device::open(&path, Some("testkey"), "alice").unwrap();
            assert!(alice.is_trusted(&bob_addr, &bik).unwrap(), "pin 必须落盘");
            let bob2 = Device::generate("bob").unwrap();
            assert!(!alice.is_trusted(&bob_addr, &bob2.identity_key().unwrap()).unwrap());
        }
        let _ = std::fs::remove_file(&path);
    }

    /// 会话持久化：握手后重开，后续普通消息（类型 2）无需重新握手即可解密。
    #[test]
    fn session_persists_and_decrypts_after_reopen() {
        let alice_path = temp_db("sess-a");
        let bob_path = temp_db("sess-b");
        let (alice_addr, bob_addr) = {
            let mut alice = Device::open(&alice_path, Some("ka"), "alice").unwrap();
            let mut bob = Device::open(&bob_path, Some("kb"), "bob").unwrap();
            let a = alice.address().clone();
            let b = bob.address().clone();
            alice.process_bundle(&b, &bob.prekey_bundle().unwrap()).unwrap();
            let (t, ct) = alice.encrypt(&b, b"handshake hello").unwrap();
            assert_eq!(bob.decrypt(&a, t, &ct).unwrap(), b"handshake hello");
            (a, b)
        };
        // 双方都重开（模拟重启），bob 回一条普通消息，alice 无需重新握手即可解密
        let mut alice = Device::open(&alice_path, Some("ka"), "alice").unwrap();
        let mut bob = Device::open(&bob_path, Some("kb"), "bob").unwrap();
        let (t2, ct2) = bob.encrypt(&alice_addr, b"after restart").unwrap();
        assert_eq!(t2, 2, "重启后应是普通 Signal 消息而非 PreKey");
        assert_eq!(
            alice.decrypt(&bob_addr, t2, &ct2).unwrap(),
            b"after restart"
        );
        let _ = std::fs::remove_file(&alice_path);
        let _ = std::fs::remove_file(&bob_path);
    }

    /// 预密钥 id 单调递增：两次出示 QR 的 bundle 不会互相覆盖。
    #[test]
    fn prekey_ids_advance() {
        let mut bob = Device::open(&temp_db("ids"), Some("k"), "bob").unwrap();
        let b1 = bob.prekey_bundle().unwrap();
        let b2 = bob.prekey_bundle().unwrap();
        let id1 = u32::from(b1.pre_key_id().unwrap().unwrap());
        let id2 = u32::from(b2.pre_key_id().unwrap().unwrap());
        assert!(id2 > id1, "预密钥 id 必须递增: {id1} -> {id2}");
    }

    /// 文件库不给 key 必须拒绝（strict 模式，与 queue::Db 同一约束）。
    #[test]
    fn file_store_requires_key() {
        let path = temp_db("nokey");
        assert!(SqlSignalStore::open(&path, None).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
