//! Signal 会话层：PQXDH(Kyber-1024 + X25519) 初始协商 → Double Ratchet 逐条换钥 → SAS 带外比对。
//!
//! 密码学原语全部来自 vendored libsignal-protocol，本模块只做编排：
//! - 初始密钥：`process_prekey_bundle` 跑 X3DH，内部 HKDF 从共享点派生根密钥（不直接用共享点当钥匙）。
//!   该 libsignal 版本的 PreKeyBundle 恒含 Kyber 预密钥，故初始握手即 PQXDH（抗量子）。
//! - 逐条消息：`message_encrypt` / `message_decrypt` 驱动 Double Ratchet，前向保密 + 后向自愈。
//! - 带外认证：SAS 由 `Fingerprint` 计算，绑定双方长期身份公钥；两端算出同一串，中间人必不匹配。
//! - 首条消息：QR 里的一次性 token 派生 keyed-BLAKE3 MAC，未扫到码者无法为第一条握手消息造出合法 MAC。
//!
//! 阶段 3 起后端为 SQLCipher 持久化 store（signal_store.rs）：generate 用内存库，
//! open 用文件库；身份/预密钥/会话/TOFU pin 全落盘，重启不丢。

use crate::signal_store::SqlSignalStore;
use crate::{CoreError, Result};
use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, Direction, Fingerprint, GenericSignedPreKey, IdentityChange,
    IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, PublicKey, SignalMessage, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// SAS Fingerprint 参数：libsignal 版本 2、Signal 惯用 5200 次迭代。
const SAS_VERSION: u32 = 2;
const SAS_ITERATIONS: u32 = 5200;

/// 本应用固定单设备，device_id 恒为 1（libsignal DeviceId::new 收 u8）。
const DEVICE_ID: u8 = 1;

fn crypto_err<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Crypto(e.to_string())
}

/// 驱动 libsignal 的 async trait：其 future 为 `?Send`，用当前线程 `block_on` 即可。
fn block<T>(
    fut: impl std::future::Future<Output = std::result::Result<T, libsignal_protocol::SignalProtocolError>>,
) -> Result<T> {
    block_on(fut).map_err(crypto_err)
}

fn now_ts() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Timestamp::from_epoch_millis(ms)
}

/// 一个设备的 Signal 端点：长期身份密钥 + 预密钥/会话存储。
///
/// 后端统一为 SQLCipher store（signal_store.rs）：`generate` 用内存库
/// （每次全新身份，测试与临时会话），`open` 用文件库（身份/会话/TOFU pin 落盘，
/// 重启不丢）。libsignal 的 InMem 实现已被替换。
pub struct Device {
    pub address: ProtocolAddress,
    store: SqlSignalStore,
}

impl Device {
    /// 内存后端：每次调用生成全新身份（测试 / 无持久化诉求的临时会话）。
    pub fn generate(name: &str) -> Result<Self> {
        Self::bootstrap(SqlSignalStore::open(std::path::Path::new(":memory:"), None)?, name)
    }

    /// SQLCipher 持久化后端：首次打开生成长期身份并落盘；之后重开沿用，
    /// 会话与 TOFU pin 均持久（strict 模式：文件库必须给 key）。
    pub fn open(path: &std::path::Path, key: Option<&str>, name: &str) -> Result<Self> {
        Self::bootstrap(SqlSignalStore::open(path, key)?, name)
    }

    /// 打开 store 后的身份引导：无本地身份则生成（长期钥 + 随机 registration_id）。
    fn bootstrap(store: SqlSignalStore, name: &str) -> Result<Self> {
        if store.local_identity()?.is_none() {
            let mut rng = rand::rng();
            let identity = IdentityKeyPair::generate(&mut rng);
            let mut reg = [0u8; 4];
            getrandom::fill(&mut reg).map_err(|e| CoreError::Entropy(e.to_string()))?;
            store.save_local_identity(&identity.serialize(), u32::from_be_bytes(reg))?;
        }
        let address = ProtocolAddress::new(name.to_owned(), DeviceId::new(DEVICE_ID).map_err(crypto_err)?);
        Ok(Self { address, store })
    }

    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    /// 本设备长期身份公钥（TOFU 首次配对后要 pin 到对方存的就是它）。
    pub fn identity_key(&self) -> Result<IdentityKey> {
        let pair = block(self.store.get_identity_key_pair())?;
        Ok(*pair.identity_key())
    }

    /// 被扫方(Bob)：生成并存储一组预密钥(一次性 + 签名 + Kyber)，产出可编入 QR 的 PreKeyBundle。
    /// 签名预密钥与 Kyber 预密钥都由长期身份钥签名，扫码方 process 时验签。
    pub fn prekey_bundle(&mut self) -> Result<PreKeyBundle> {
        let mut rng = rand::rng();
        let identity_pair = block(self.store.get_identity_key_pair())?;

        let pre_key = KeyPair::generate(&mut rng);
        let signed_pre_key = KeyPair::generate(&mut rng);
        let kyber_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        // 单调 id：每次出示 QR 生成新组，固定 id 会覆盖上一组悬而未决的预密钥
        let pk_id = PreKeyId::from(self.store.next_prekey_id("pre_keys")?);
        let spk_id = SignedPreKeyId::from(self.store.next_prekey_id("signed_pre_keys")?);
        let kpk_id = KyberPreKeyId::from(self.store.next_prekey_id("kyber_pre_keys")?);

        let spk_sig = identity_pair
            .private_key()
            .calculate_signature(&signed_pre_key.public_key.serialize(), &mut rng)
            .map_err(crypto_err)?;
        let kpk_sig = identity_pair
            .private_key()
            .calculate_signature(&kyber_key.public_key.serialize(), &mut rng)
            .map_err(crypto_err)?;

        block(self.store.save_pre_key(pk_id, &PreKeyRecord::new(pk_id, &pre_key)))?;
        block(self.store.save_signed_pre_key(
            spk_id,
            &SignedPreKeyRecord::new(spk_id, now_ts(), &signed_pre_key, &spk_sig),
        ))?;
        block(self.store.save_kyber_pre_key(
            kpk_id,
            &KyberPreKeyRecord::new(kpk_id, now_ts(), &kyber_key, &kpk_sig),
        ))?;

        let reg_id = block(self.store.get_local_registration_id())?;
        PreKeyBundle::new(
            reg_id,
            DeviceId::new(DEVICE_ID).map_err(crypto_err)?,
            Some((pk_id, pre_key.public_key)),
            spk_id,
            signed_pre_key.public_key,
            spk_sig.to_vec(),
            kpk_id,
            kyber_key.public_key.clone(),
            kpk_sig.to_vec(),
            *identity_pair.identity_key(),
        )
        .map_err(crypto_err)
    }

    /// 扫码方(Alice)：用 Bob 的 PreKeyBundle 跑 PQXDH 建立会话。
    /// 内部会验签名预密钥/Kyber 预密钥的身份签名，并按 TOFU 校验对方身份。
    pub fn process_bundle(&mut self, remote: &ProtocolAddress, bundle: &PreKeyBundle) -> Result<()> {
        let mut rng = rand::rng();
        // 两个 &mut dyn 不能同时借自一个对象 → 传共享连接的克隆（见 signal_store.rs）
        let mut session = self.store.clone();
        let mut identity = self.store.clone();
        block(process_prekey_bundle(
            remote,
            &self.address,
            &mut session,
            &mut identity,
            bundle,
            SystemTime::now(),
            &mut rng,
        ))
    }

    /// 发一条消息（Double Ratchet 自动换钥）。返回 (线格式类型字节, 密文)。
    pub fn encrypt(&mut self, remote: &ProtocolAddress, plaintext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut rng = rand::rng();
        let mut session = self.store.clone();
        let mut identity = self.store.clone();
        let msg = block(message_encrypt(
            plaintext,
            remote,
            &self.address,
            &mut session,
            &mut identity,
            SystemTime::now(),
            &mut rng,
        ))?;
        Ok((type_byte(&msg), msg.serialize().to_vec()))
    }

    /// 收一条消息：按类型字节重建 CiphertextMessage 再走 Double Ratchet 解密。
    pub fn decrypt(
        &mut self,
        remote: &ProtocolAddress,
        msg_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rng = rand::rng();
        let cm = match msg_type {
            3 => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(ciphertext).map_err(crypto_err)?,
            ),
            2 => CiphertextMessage::SignalMessage(
                SignalMessage::try_from(ciphertext).map_err(crypto_err)?,
            ),
            other => {
                return Err(CoreError::Crypto(format!(
                    "unsupported ciphertext type {other}"
                )))
            }
        };
        // 五个 store 参数（一个 &dyn + 四个 &mut dyn）各传一份共享连接的克隆
        // （单一对象无法同时借出多个 &mut，见 signal_store.rs 模块注释）
        let mut session = self.store.clone();
        let mut identity = self.store.clone();
        let mut prekey = self.store.clone();
        let signed = self.store.clone();
        let mut kyber = self.store.clone();
        block(message_decrypt(
            &cm,
            remote,
            &self.address,
            &mut session,
            &mut identity,
            &mut prekey,
            &signed,
            &mut kyber,
            &mut rng,
        ))
    }

    /// TOFU：首次带外(SAS)验证通过后，把对方长期身份公钥 pin 下来。
    /// 返回身份变更状态（首次为 NoChange/Changed，据此判断是否需重新验证）。
    pub fn pin_identity(
        &mut self,
        remote: &ProtocolAddress,
        key: &IdentityKey,
    ) -> Result<IdentityChange> {
        block(self.store.save_identity(remote, key))
    }

    /// 校验某长期身份公钥是否被本设备信任（重连时免扫码的关键判定）。
    pub fn is_trusted(&self, remote: &ProtocolAddress, key: &IdentityKey) -> Result<bool> {
        block(
            self.store
                .is_trusted_identity(remote, key, Direction::Receiving),
        )
    }
}

/// CiphertextMessage → 线格式类型字节（与 libsignal CiphertextMessageType 的 repr 一致）。
fn type_byte(msg: &CiphertextMessage) -> u8 {
    match msg.message_type() {
        CiphertextMessageType::Whisper => 2,
        CiphertextMessageType::PreKey => 3,
        CiphertextMessageType::SenderKey => 7,
        CiphertextMessageType::Plaintext => 8,
    }
}

/// SAS 带外安全码：两端各自调用，绑定双方长期身份公钥，产出同一串。
/// 中间人与两边分别协商，看到的对方身份钥不同 → 安全码必然对不上，肉眼比对即可识破。
/// 返回 (完整显示串, 6 位短码)；短码由完整串再哈希取模，两端一致且不可被单方操纵。
pub fn sas_code(
    local_id: &[u8],
    local_key: &IdentityKey,
    remote_id: &[u8],
    remote_key: &IdentityKey,
) -> Result<(String, String)> {
    let fp = Fingerprint::new(
        SAS_VERSION,
        SAS_ITERATIONS,
        local_id,
        local_key,
        remote_id,
        remote_key,
    )
    .map_err(|e| CoreError::Crypto(format!("{e:?}")))?;
    let full = fp
        .display_string()
        .map_err(|e| CoreError::Crypto(format!("{e:?}")))?;

    let digest = blake3::Hasher::new()
        .update(b"dc-sas6-v1")
        .update(full.as_bytes())
        .finalize();
    let mut four = [0u8; 4];
    four.copy_from_slice(&digest.as_bytes()[..4]);
    let code = u32::from_be_bytes(four) % 1_000_000;
    Ok((full, format!("{code:06}")))
}

/// 首条握手消息的带外认证 MAC：用 QR 里的一次性 token + 桶地址派生 keyed-BLAKE3 密钥。
/// 没当面扫到码（拿不到 token）的人无法为第一条 PreKeySignalMessage 造出合法 MAC。
pub fn first_message_mac(token: &[u8], bucket: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let key = crate::mailbox::derive_mailbox_secret(token, bucket, 0);
    *blake3::Hasher::new_keyed(&key)
        .update(b"dc-first-msg-v1")
        .update(ciphertext)
        .finalize()
        .as_bytes()
}

/// 校验首条握手消息的 token-MAC（常量时间比较）。
pub fn verify_first_message_mac(
    token: &[u8],
    bucket: &[u8; 32],
    ciphertext: &[u8],
    mac: &[u8; 32],
) -> Result<()> {
    let expected = first_message_mac(token, bucket, ciphertext);
    let diff = mac
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(CoreError::Crypto("first-message token mac mismatch".into()));
    }
    Ok(())
}

/// PreKeyBundle 的上线格式：QR 分帧 / 蓝牙字节通道承载它。
/// 用公开 getter 抽字段（id 类型 derive 了 Into<u32>，公钥/身份钥走各自 serialize），
/// CBOR 打包；对端用 PreKeyBundle::new 精确重建，字段一一对应。
#[derive(Serialize, Deserialize)]
struct WirePreKeyBundle {
    registration_id: u32,
    device_id: u8,
    pre_key_id: Option<u32>,
    pre_key_public: Option<Vec<u8>>,
    signed_pre_key_id: u32,
    signed_pre_key_public: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    kyber_pre_key_id: u32,
    kyber_pre_key_public: Vec<u8>,
    kyber_pre_key_signature: Vec<u8>,
    identity_key: Vec<u8>,
}

/// 把 PreKeyBundle 序列化成可放进 QR / 走蓝牙的字节。
pub fn bundle_to_wire(bundle: &PreKeyBundle) -> Result<Vec<u8>> {
    let w = WirePreKeyBundle {
        registration_id: bundle.registration_id().map_err(crypto_err)?,
        device_id: u8::from(bundle.device_id().map_err(crypto_err)?),
        pre_key_id: bundle.pre_key_id().map_err(crypto_err)?.map(u32::from),
        pre_key_public: bundle
            .pre_key_public()
            .map_err(crypto_err)?
            .map(|k| k.serialize().to_vec()),
        signed_pre_key_id: u32::from(bundle.signed_pre_key_id().map_err(crypto_err)?),
        signed_pre_key_public: bundle
            .signed_pre_key_public()
            .map_err(crypto_err)?
            .serialize()
            .to_vec(),
        signed_pre_key_signature: bundle.signed_pre_key_signature().map_err(crypto_err)?.to_vec(),
        kyber_pre_key_id: u32::from(bundle.kyber_pre_key_id().map_err(crypto_err)?),
        kyber_pre_key_public: bundle
            .kyber_pre_key_public()
            .map_err(crypto_err)?
            .serialize()
            .to_vec(),
        kyber_pre_key_signature: bundle.kyber_pre_key_signature().map_err(crypto_err)?.to_vec(),
        identity_key: bundle.identity_key().map_err(crypto_err)?.serialize().to_vec(),
    };
    let mut buf = Vec::with_capacity(2048);
    ciborium::ser::into_writer(&w, &mut buf).map_err(|e| CoreError::Cbor(e.to_string()))?;
    Ok(buf)
}

/// 从 QR / 蓝牙收到的字节重建 PreKeyBundle（扫码方 process 之前的入口）。
pub fn bundle_from_wire(bytes: &[u8]) -> Result<PreKeyBundle> {
    let w: WirePreKeyBundle =
        ciborium::de::from_reader(bytes).map_err(|e| CoreError::Cbor(e.to_string()))?;
    let pre_key = match (w.pre_key_id, w.pre_key_public) {
        (Some(id), Some(pk)) => Some((
            PreKeyId::from(id),
            PublicKey::try_from(pk.as_slice()).map_err(crypto_err)?,
        )),
        _ => None,
    };
    PreKeyBundle::new(
        w.registration_id,
        DeviceId::new(w.device_id).map_err(crypto_err)?,
        pre_key,
        SignedPreKeyId::from(w.signed_pre_key_id),
        PublicKey::try_from(w.signed_pre_key_public.as_slice()).map_err(crypto_err)?,
        w.signed_pre_key_signature,
        KyberPreKeyId::from(w.kyber_pre_key_id),
        kem::PublicKey::deserialize(&w.kyber_pre_key_public).map_err(crypto_err)?,
        w.kyber_pre_key_signature,
        IdentityKey::decode(&w.identity_key).map_err(crypto_err)?,
    )
    .map_err(crypto_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PQXDH 建会话 + Double Ratchet 双向收发；连续消息密钥各不相同。
    #[test]
    fn pqxdh_double_ratchet_roundtrip() {
        let mut alice = Device::generate("alice-uuid").unwrap();
        let mut bob = Device::generate("bob-uuid").unwrap();
        let bob_addr = bob.address().clone();
        let alice_addr = alice.address().clone();

        let bundle = bob.prekey_bundle().unwrap();
        alice.process_bundle(&bob_addr, &bundle).unwrap();

        // Alice 首条为 PreKey 消息(类型 3)
        let (t1, ct1) = alice.encrypt(&bob_addr, b"hello bob").unwrap();
        assert_eq!(t1, 3);
        assert_eq!(bob.decrypt(&alice_addr, t1, &ct1).unwrap(), b"hello bob");

        // Bob 回复，双向棘轮打通
        let (t2, ct2) = bob.encrypt(&alice_addr, b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&bob_addr, t2, &ct2).unwrap(), b"hi alice");

        // 之后 Alice 发普通 Signal 消息(类型 2)，逐条换钥 → 密文互异
        let (t3, ct3) = alice.encrypt(&bob_addr, b"msg3").unwrap();
        let (t4, ct4) = alice.encrypt(&bob_addr, b"msg4").unwrap();
        assert_eq!(t3, 2);
        assert_ne!(ct3, ct4);
        assert_eq!(bob.decrypt(&alice_addr, t3, &ct3).unwrap(), b"msg3");
        assert_eq!(bob.decrypt(&alice_addr, t4, &ct4).unwrap(), b"msg4");
    }

    /// 重放同一密文必须失败（棘轮消息密钥已消费）。
    #[test]
    fn replay_same_ciphertext_rejected() {
        let mut alice = Device::generate("a").unwrap();
        let mut bob = Device::generate("b").unwrap();
        let bob_addr = bob.address().clone();
        let alice_addr = alice.address().clone();
        let bundle = bob.prekey_bundle().unwrap();
        alice.process_bundle(&bob_addr, &bundle).unwrap();

        let (t, ct) = alice.encrypt(&bob_addr, b"once").unwrap();
        assert_eq!(bob.decrypt(&alice_addr, t, &ct).unwrap(), b"once");
        assert!(
            bob.decrypt(&alice_addr, t, &ct).is_err(),
            "重放同一密文必须被拒"
        );
    }

    /// 篡改密文（MAC 覆盖范围）必须解密失败。
    #[test]
    fn tampered_ciphertext_rejected() {
        let mut alice = Device::generate("a").unwrap();
        let mut bob = Device::generate("b").unwrap();
        let bob_addr = bob.address().clone();
        let alice_addr = alice.address().clone();
        let bundle = bob.prekey_bundle().unwrap();
        alice.process_bundle(&bob_addr, &bundle).unwrap();

        let (t, mut ct) = alice.encrypt(&bob_addr, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(bob.decrypt(&alice_addr, t, &ct).is_err());
    }

    /// SAS：诚实两端一致；身份钥被替换(中间人)必不一致；短码为 6 位。
    #[test]
    fn sas_matches_and_detects_identity_substitution() {
        let alice = Device::generate("a").unwrap();
        let bob = Device::generate("b").unwrap();
        let aik = alice.identity_key().unwrap();
        let bik = bob.identity_key().unwrap();

        let (a_full, a6) = sas_code(b"alice", &aik, b"bob", &bik).unwrap();
        let (b_full, b6) = sas_code(b"bob", &bik, b"alice", &aik).unwrap();
        assert_eq!(a_full, b_full, "诚实两端安全码必须一致");
        assert_eq!(a6, b6);
        assert_eq!(a6.len(), 6);

        // 中间人：Alice 以为在跟 Bob，实际拿到 Mallory 的长期钥 → 安全码变化
        let mallory = Device::generate("m").unwrap();
        let mk = mallory.identity_key().unwrap();
        let (_, a6_mitm) = sas_code(b"alice", &aik, b"bob", &mk).unwrap();
        assert_ne!(a6, a6_mitm, "SAS 必须识别身份钥替换(中间人)");
    }

    /// TOFU：首次未 pin 时按信任处理；pin 后同钥可信、换长期钥不可信（需重新带外验证）。
    #[test]
    fn tofu_pin_and_identity_change() {
        let mut alice = Device::generate("a").unwrap();
        let bob = Device::generate("b").unwrap();
        let bob_addr = bob.address().clone();
        let bik = bob.identity_key().unwrap();

        // 首次：尚无记录 → TOFU 接受
        assert!(alice.is_trusted(&bob_addr, &bik).unwrap());
        alice.pin_identity(&bob_addr, &bik).unwrap();
        assert!(alice.is_trusted(&bob_addr, &bik).unwrap());

        // 同一地址换了长期钥 → 不再可信
        let bob2 = Device::generate("b").unwrap();
        let bik2 = bob2.identity_key().unwrap();
        assert!(!alice.is_trusted(&bob_addr, &bik2).unwrap());
    }

    /// 首条消息 token-MAC：正确 token 通过；错 token / 改密文均拒。
    #[test]
    fn first_message_token_mac() {
        let token = [7u8; 48];
        let bucket = [9u8; 32];
        let ct = b"prekey-signal-message-bytes";
        let mac = first_message_mac(&token, &bucket, ct);
        verify_first_message_mac(&token, &bucket, ct, &mac).unwrap();

        let wrong_token = [8u8; 48];
        assert!(verify_first_message_mac(&wrong_token, &bucket, ct, &mac).is_err());

        let mut tampered = ct.to_vec();
        tampered[0] ^= 1;
        assert!(verify_first_message_mac(&token, &bucket, &tampered, &mac).is_err());
    }

    /// 上线格式往返：bundle 序列化成字节再重建，仍能正常 process 并收发。
    #[test]
    fn bundle_wire_roundtrip_usable() {
        let mut alice = Device::generate("a").unwrap();
        let mut bob = Device::generate("b").unwrap();
        let alice_addr = alice.address().clone();
        let bob_addr = bob.address().clone();
        let wire = bundle_to_wire(&bob.prekey_bundle().unwrap()).unwrap();
        alice
            .process_bundle(&bob_addr, &bundle_from_wire(&wire).unwrap())
            .unwrap();
        let (t, ct) = alice.encrypt(&bob_addr, b"roundtrip").unwrap();
        assert_eq!(bob.decrypt(&alice_addr, t, &ct).unwrap(), b"roundtrip");
    }

    /// 端到端连接流程（模拟「扫码拼接 + 蓝牙字节通道」）：
    /// Bob 出示 bundle → 上线格式 → Alice 扫码拼接后重建并跑 PQXDH →
    /// 首条消息带 token-MAC（Bob 先验 MAC 再解密）→ 双向 SAS 一致（用户肉眼比对）→
    /// TOFU pin 对方长期钥 → 之后双向 Double Ratchet 加密聊天。
    #[test]
    fn full_connection_flow_over_wire() {
        let token = [0x5Au8; 48];
        let bucket = [0x3Cu8; 32];

        let mut alice = Device::generate("alice-uuid").unwrap();
        let mut bob = Device::generate("bob-uuid").unwrap();
        let alice_addr = alice.address().clone();
        let bob_addr = bob.address().clone();

        // 1) Bob 出示：bundle → QR/蓝牙字节；2) Alice 扫码拼接后重建，跑 PQXDH
        let wire = bundle_to_wire(&bob.prekey_bundle().unwrap()).unwrap();
        alice
            .process_bundle(&bob_addr, &bundle_from_wire(&wire).unwrap())
            .unwrap();

        // 3) Alice 发首条握手消息 + token-MAC；Bob 先验带外 MAC 再解密
        let (t1, ct1) = alice.encrypt(&bob_addr, b"handshake hello").unwrap();
        let mac = first_message_mac(&token, &bucket, &ct1);
        verify_first_message_mac(&token, &bucket, &ct1, &mac).unwrap();
        assert_eq!(bob.decrypt(&alice_addr, t1, &ct1).unwrap(), b"handshake hello");

        // 4) 双方各自算 SAS：必须一致（否则说明被中间人，用户比对 6 位短码即可发现）
        let aik = alice.identity_key().unwrap();
        let bik = bob.identity_key().unwrap();
        let (_, a6) = sas_code(b"alice", &aik, b"bob", &bik).unwrap();
        let (_, b6) = sas_code(b"bob", &bik, b"alice", &aik).unwrap();
        assert_eq!(a6, b6, "连接后两端 SAS 必须一致");

        // 5) 比对通过 → TOFU pin 对方长期钥（此后重连免扫码）
        alice.pin_identity(&bob_addr, &bik).unwrap();
        bob.pin_identity(&alice_addr, &aik).unwrap();

        // 6) 之后双向 Double Ratchet 加密聊天
        let (t2, ct2) = bob.encrypt(&alice_addr, b"hi alice, connected").unwrap();
        assert_eq!(
            alice.decrypt(&bob_addr, t2, &ct2).unwrap(),
            b"hi alice, connected"
        );
        let (t3, ct3) = alice.encrypt(&bob_addr, b"msg after connect").unwrap();
        assert_eq!(bob.decrypt(&alice_addr, t3, &ct3).unwrap(), b"msg after connect");
    }
}
