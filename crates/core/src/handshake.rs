//! Signal 会话层：PQXDH(Kyber-1024 + X25519) 初始协商 → Double Ratchet 逐条换钥 → SAS 带外比对。
//!
//! 密码学原语全部来自 vendored libsignal-protocol，本模块只做编排：
//! - 初始密钥：`process_prekey_bundle` 跑 X3DH，内部 HKDF 从共享点派生根密钥（不直接用共享点当钥匙）。
//!   该 libsignal 版本的 PreKeyBundle 恒含 Kyber 预密钥，故初始握手即 PQXDH（抗量子）。
//! - 逐条消息：`message_encrypt` / `message_decrypt` 驱动 Double Ratchet，前向保密 + 后向自愈。
//! - 带外认证：SAS 由 `Fingerprint` 计算，绑定双方长期身份公钥；两端算出同一串，中间人必不匹配。
//! - 首条消息：QR 里的一次性 token 派生 keyed-BLAKE3 MAC，未扫到码者无法为第一条握手消息造出合法 MAC。
//!
//! 阶段 1 用 libsignal 的内存 store 证明链路正确；SQLCipher 持久化(TOFU pin)与 UniFFI 导出在后续阶段接入，
//! store trait 边界已就位。

use crate::{CoreError, Result};
use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, Direction, Fingerprint, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage,
    PreKeyStore, ProtocolAddress, SignalMessage, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

/// SAS Fingerprint 参数：libsignal 版本 2、Signal 惯用 5200 次迭代。
const SAS_VERSION: u32 = 2;
const SAS_ITERATIONS: u32 = 5200;

/// 本应用固定单设备，device_id 恒为 1。
const DEVICE_ID: u32 = 1;

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
/// 阶段 1 后端是 libsignal 内存 store；后续以 SQLCipher 实现同一组 trait 即可无缝替换。
pub struct Device {
    pub address: ProtocolAddress,
    store: InMemSignalProtocolStore,
}

impl Device {
    /// 生成新设备：预生成长期身份密钥对（TOFU 的信任根），随机 registration_id。
    pub fn generate(name: &str) -> Result<Self> {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let mut reg = [0u8; 4];
        getrandom::fill(&mut reg).map_err(|e| CoreError::Entropy(e.to_string()))?;
        let store =
            InMemSignalProtocolStore::new(identity, u32::from_be_bytes(reg)).map_err(crypto_err)?;
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
        let mut rng = OsRng;
        let identity_pair = block(self.store.get_identity_key_pair())?;

        let pre_key = KeyPair::generate(&mut rng);
        let signed_pre_key = KeyPair::generate(&mut rng);
        let kyber_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        let pk_id = PreKeyId::from(1u32);
        let spk_id = SignedPreKeyId::from(1u32);
        let kpk_id = KyberPreKeyId::from(1u32);

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
        let mut rng = OsRng;
        block(process_prekey_bundle(
            remote,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            bundle,
            SystemTime::now(),
            &mut rng,
        ))
    }

    /// 发一条消息（Double Ratchet 自动换钥）。返回 (线格式类型字节, 密文)。
    pub fn encrypt(&mut self, remote: &ProtocolAddress, plaintext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut rng = OsRng;
        let msg = block(message_encrypt(
            plaintext,
            remote,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
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
        let mut rng = OsRng;
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
        block(message_decrypt(
            &cm,
            remote,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
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
}
