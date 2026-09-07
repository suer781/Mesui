//! iroh 两 endpoint 进程内对连。
//! 验证：按公钥(endpoint id)寻址 + 直连 UDP + QUIC 双向流收发。
//! 阶段 5 的远程通道以此为地基；relay 全禁用保证测试确定性。

#![cfg(feature = "iroh-net")]

use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, RelayMode, TransportAddr, endpoint::presets};

const ALPN: &[u8] = b"dc-spike/1";

#[tokio::test]
async fn two_endpoints_exchange_message() {
    tokio::time::timeout(Duration::from_secs(30), async move {
        let alpns = vec![ALPN.to_vec()];

        // 接收方：声明 ALPN，禁 relay，绑随机端口
        let acceptor = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .alpns(alpns)
            .bind()
            .await
            .expect("acceptor bind");

        // 拨号方：同一进程内第二个 endpoint
        let dialer = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("dialer bind");

        let peer_id = acceptor.id();
        // relay 禁用时 online() 语义未知：限时等待，超时也继续（直连地址通常已就绪）
        let _ = tokio::time::timeout(Duration::from_secs(5), acceptor.online()).await;
        let peer_addr = acceptor
            .addr()
            .ip_addrs()
            .copied()
            .find(|a| a.ip().is_loopback())
            .or_else(|| acceptor.addr().ip_addrs().copied().next())
            .expect("acceptor direct address");

        // 接收循环：收到连接 → 读一个请求 → 回一个应答
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = acceptor.accept().await {
                let conn = incoming
                    .accept()
                    .expect("incoming accept")
                    .await
                    .expect("connection established");
                let remote = conn.remote_id().to_string();
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
                let _req = recv.read_to_end(1024).await.expect("read request");
                let reply = format!("pong from {remote}");
                send.write_all(reply.as_bytes()).await.expect("write reply");
                send.finish().expect("finish");
                conn.closed().await;
            }
        });

        // 拨号：按公钥 + 直连 IP 建连
        let addr = EndpointAddr::from_parts(peer_id, [TransportAddr::Ip(peer_addr)]);
        let conn = dialer.connect(addr, ALPN).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"ping").await.expect("write ping");
        send.finish().expect("finish");
        let back = recv.read_to_end(1024).await.expect("read reply");
        assert_eq!(back, format!("pong from {}", dialer.id()).into_bytes());

        conn.close(0u32.into(), b"bye");
        dialer.close().await;
        accept_task.abort();
    })
    .await
    .expect("spike timed out");
}
