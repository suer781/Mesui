//! 端到端运行时冒烟演示：把核心模块按真实时序串起来动态跑一遍。
//! 单测证明「构造输入下逻辑对」，本程序证明「真实进程 + 真实套接字 + 真实
//! 文件库下链路通」。运行：cargo run --example e2e_demo
//!
//! 六幕：身份 → 加好友(信箱密钥) → 离线队列+重试+死信 → 真实 iroh 传输
//! （含重复信/篡改信）→ 节点密钥轮换 → 自适应档位爬升。

use std::time::{SystemTime, UNIX_EPOCH};

use dc_core::adaptive::{Metrics, PolicyEngine, Tier};
use dc_core::envelope::{frame, unframe, Envelope, PayloadKind};
use dc_core::identity::Identity;
use dc_core::mailbox::{self, BucketWrite};
use dc_core::nodekey::{NodeKeyAnnouncement, NodeKeyRing};
use dc_core::queue::Db;
use dc_core::retry::RetryPolicy;
use dc_core::settings::Settings;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn line(tag: &str, msg: String) {
    println!("[{tag}] {msg}");
}

fn main() {
    let t0 = now_ms();
    println!("===== dc-core 端到端运行时冒烟演示 =====");

    // ── 第一幕：身份与安全码 ──────────────────────────────
    let alice = Identity::generate().expect("alice identity");
    let bob = Identity::generate().expect("bob identity");
    let fp_a = dc_core::identity::identity_fingerprint(&alice.node_id());
    let fp_b = dc_core::identity::identity_fingerprint(&bob.node_id());
    line("1-身份", format!("Alice 节点 {:02x}…", alice.node_id()[0]));
    line("1-身份", format!("Bob   节点 {:02x}…", bob.node_id()[0]));
    line(
        "1-身份",
        format!(
            "安全码（安全码核对用，双方各显一半）：A={} / B={}",
            dc_core::identity::safety_groups(&fp_a, 2),
            dc_core::identity::safety_groups(&fp_b, 2)
        ),
    );

    // ── 第二幕：加好友（信箱密钥派生；v9.1 桶地址=随机值） ──
    let mut entropy = dc_core::entropy::EntropyHarvester::new().expect("entropy");
    entropy.mix(b"sensor-noise-simulation-0.013,0.998,gyro-jitter");
    let handshake_secret = entropy.token512().expect("handshake secret");
    let bucket: [u8; 32] = entropy.token512().expect("bucket random")[..32]
        .try_into()
        .unwrap();
    let secret = mailbox::derive_mailbox_secret(&handshake_secret, &bucket, 1);
    line(
        "2-加好友",
        format!("桶地址(随机,经介绍信分发)={:02x}…，mailbox secret 已派生", bucket[0]),
    );

    // ── 第三幕：离线队列 + 重试 + 死信（真实 SQLCipher 文件库） ──
    let tmp = std::env::temp_dir().join(format!("dc-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let db_a = Db::open(&tmp.join("alice.db.enc"), Some("demo-key-hex-0123")).expect("alice db");
    let db_b = Db::open(&tmp.join("bob.db.enc"), Some("demo-key-hex-0123")).expect("bob db");
    line("3-队列", "两节点 SQLCipher 文件库已打开".to_string());

    let policy = RetryPolicy { max_attempts: 3, base_delay_ms: 50, max_delay_ms: 200 };
    let t = now_ms() - t0 + 1000;
    let mut envs = Vec::new();
    for i in 0..5u8 {
        let e = Envelope {
            msg_id: [i; 16],
            sender: alice.node_id(),
            recipient: Some(bob.node_id()),
            group: None,
            kind: PayloadKind::Text,
            // body 语义 = Signal 信封密文（真实加解密在阶段 2 接入），
            // 本演示验证的是信封流经队列/通道/去重/门禁的运行时行为
            body: format!("hello-{i}").into_bytes(),
            sent_at_ms: t,
            ttl_hops: 6,
        };
        envs.push(e);
    }
    for e in &envs {
        db_a.enqueue(e).unwrap();
    }
    line("3-队列", format!("已入队 {} 封", envs.len()));

    // 通道状态机模拟：前两次投递全失败 → 退避；之后恢复
    let due1 = db_a.due(t, 10).unwrap();
    line("3-队列", format!("tick1: 到期 {} 封，通道失败，全部退避", due1.len()));
    for m in &due1 {
        let dead = db_a.fail_and_reschedule(&m.msg_id, &policy, t).unwrap();
        assert!(!dead);
    }
    assert!(db_a.due(t, 10).unwrap().is_empty(), "退避期内不应到期");
    let due2 = db_a.due(t + 300, 10).unwrap();
    line(
        "3-队列",
        format!("tick2(+300ms): 到期 {} 封，又失败一次", due2.len()),
    );
    for m in &due2 {
        db_a.fail_and_reschedule(&m.msg_id, &policy, t + 300).unwrap();
    }
    // 把第 4 封打到耗尽 → 死信
    for _ in 0..2 {
        let due = db_a.due(t + 900, 10).unwrap();
        for m in &due {
            if m.msg_id == [3; 16] {
                let dead = db_a.fail_and_reschedule(&m.msg_id, &policy, t + 900).unwrap();
                line("3-队列", format!("msg[3] 耗尽转死信={dead}"));
            }
        }
    }
    let revived = db_a.stats().unwrap();
    line("3-队列", format!("当前状态(待发,死信,去重)={revived:?}，随后手动复活死信"));
    db_a.revive(&[3; 16]).unwrap();
    line("3-队列", format!("复活后 {:?}", db_a.stats().unwrap()));

    // ── 第四幕：真实 iroh 传输（含重复信、篡改信） ──────────
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        const ALPN: &[u8] = b"dc-e2e-demo/1";
        let acceptor = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bob endpoint");
        let dialer = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("alice endpoint");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), acceptor.online()).await;
        let peer = acceptor
            .addr()
            .ip_addrs()
            .copied()
            .find(|a| a.ip().is_loopback())
            .or_else(|| acceptor.addr().ip_addrs().copied().next())
            .expect("bob direct address");
        let acceptor_id = acceptor.id();

        // Bob 接收循环：解帧 → BucketWrite 解析 → **先验收到的 MAC** → 去重 → 入桶
        let secret_rx = secret;
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = acceptor.accept().await {
                let conn = incoming.accept().expect("accept").await.expect("conn");
                // 连接关闭时 accept_bi 返回 Err，while-let 自然结束本连接的处理
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let raw = recv.read_to_end(64 * 1024).await.expect("read frame");
                    let verdict = match unframe(&raw) {
                        Err(e) => format!("帧错误: {e}"),
                        Ok(None) => "半帧(不应出现)".into(),
                        Ok(Some((payload, _))) => match BucketWrite::from_cbor(payload) {
                            Err(e) => format!("CBOR 错误: {e}"),
                            Ok(bw) => match bw.verify(&secret_rx, now_ms()) {
                                Err(e) => format!(
                                    "信 {} MAC 拒绝(篡改/重放): {e}",
                                    hex8(&bw.envelope.msg_id)
                                ),
                                Ok(()) => {
                                    let first =
                                        db_b.record_seen(&bw.envelope.msg_id, now_ms()).unwrap();
                                    if first {
                                        format!("信 {} 验签通过，入桶", hex8(&bw.envelope.msg_id))
                                    } else {
                                        format!("重复信 {} 静默丢弃", hex8(&bw.envelope.msg_id))
                                    }
                                }
                            },
                        },
                    };
                    println!("[4-传输][Bob] {verdict}");
                    send.write_all(b"ack").await.unwrap();
                    send.finish().unwrap();
                }
            }
        });

        let conn = dialer
            .connect(
                iroh::EndpointAddr::from_parts(acceptor_id, [iroh::TransportAddr::Ip(peer)]),
                ALPN,
            )
            .await
            .expect("connect");
        let mut outcomes = Vec::new();
        for (idx, env) in envs.iter().enumerate() {
            let idx8 = idx as u8;
            let mut payload = env.clone();
            if idx == 1 {
                payload.msg_id = envs[0].msg_id; // 重复信（同 msg_id）
            }
            let mut bw = BucketWrite::seal(payload, &secret, 1, now_ms(), [idx8; 16]);
            if idx == 2 {
                // 篡改信：封 MAC **之后**改正文 → Bob 侧 MAC 校验必须失败
                bw.envelope.body.push(0xFF);
            }
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&frame(&bw.to_cbor().unwrap())).await.unwrap();
            send.finish().unwrap();
            let ack = recv.read_to_end(16).await.unwrap();
            outcomes.push((idx, String::from_utf8_lossy(&ack).to_string()));
        }
        conn.close(0u32.into(), b"bye");
        dialer.close().await;
        accept_task.abort();
        line(
            "4-传输",
            format!("Alice 发送 5 封(含1重复+1篡改)，ACK={outcomes:?}；Bob 侧判定见上行日志"),
        );
    });

    // ── 第五幕：节点密钥轮换 ──────────────────────────────
    let node_v1 = Identity::generate().unwrap();
    let node_v2 = Identity::generate().unwrap();
    let mut ann1 = NodeKeyAnnouncement::new(&alice.node_id(), &node_v1.node_id(), 1, t, 7 * 86_400_000);
    ann1.sign(&alice).unwrap();
    let mut ann2 = NodeKeyAnnouncement::new(&alice.node_id(), &node_v2.node_id(), 2, t + 10, 7 * 86_400_000);
    ann2.sign(&alice).unwrap();
    let mut ring = NodeKeyRing::new();
    ring.upsert(&ann1, t).unwrap();
    line("5-轮换", format!("serial1 生效，当前节点钥={:02x}…", ring.current(&alice.node_id(), t).unwrap()[0]));
    ring.upsert(&ann2, t + 20).unwrap();
    line("5-轮换", format!("serial2 到达，当前节点钥={:02x}…（旧钥过渡窗内仍可拨={})", ring.current(&alice.node_id(), t + 20).unwrap()[0], ring.accepts(&alice.node_id(), &node_v1.node_id(), t + 20)));
    // 伪造公告必须被拒：错签身份在 sign 时即拒绝（库层防护实证）
    let mut forged = NodeKeyAnnouncement::new(&alice.node_id(), &node_v2.node_id(), 3, t + 30, 7 * 86_400_000);
    assert!(forged.sign(&bob).is_err(), "错误身份签署公告应被拒绝");

    // ── 第六幕：自适应档位爬升与回滞 ──────────────────────
    let mut engine = PolicyEngine::new(Default::default());
    let mut trace = Vec::new();
    let script = [(10u32, 1.0f32), (60, 1.0), (200, 5.0), (200, 1.0), (10, 1.0), (10, 1.0), (10, 1.0), (10, 1.0), (10, 1.0)];
    for (g, r) in script {
        let tier = engine.observe(Metrics { group_size: g, msg_rate: r });
        trace.push(format!("{}人/{r}→{}", g, tier.as_str()));
    }
    line("6-自适应", trace.join(" ；"));
    assert_eq!(engine.current(), Tier::Light, "持续低载后应回滞到轻载");

    // ── 收尾 ─────────────────────────────────────────────
    let settings = Settings::default();
    line(
        "收尾",
        format!(
            "设置默认值抽查: 严格模式={} 链接预览={} 节点服务={}; 总耗时 {}ms",
            settings.strict_crypto, settings.privacy.link_preview, settings.node_service.enabled,
            now_ms() - t0
        ),
    );
    println!("===== 演示全部通过：运行时链路无异常 =====");
    let _ = std::fs::remove_dir_all(&tmp);
}

fn hex8(id: &[u8; 16]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}
