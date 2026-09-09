//! iroh 远程节点（阶段 5）：常驻 QUIC 端点，联系人间跨网络直连收发。
//!
//! v9 红线：零 n0 依赖——不用 presets::N0 的 DNS 发现与默认中继。地址只来自
//! 二维码携带的「节点地址快照」（本端直连 IP 列表 + 可选自建中继 URL），联系人
//! 表落盘该快照；发消息按快照建连（同 WiFi/热点直连命中，配了自建中继则可跨网）。
//!
//! 信道协议：一条消息 = 一个双向 QUIC 流，发送方写满后 finish，接收方读
//! `read_to_end` 交上层并回 1 字节 ACK——send 返回即「对端应用层已收」。
//! 载荷语义（msg_type+密文）与 BLE Wire.MSG 体一致，由 FFI 上层（Kotlin）
//! 统一解密落库，本模块只管不透明字节管道。

use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr, endpoint::presets};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 消息通道 ALPN。语义升级（帧格式变更）时换 v2 与旧版并行共存。
pub const ALPN: &[u8] = b"dc-chat/msg/1";
/// 单条消息上限：聊天文本远小于此；防恶意超长占内存。
pub const MAX_MSG_LEN: usize = 256 * 1024;
/// 建连兜底超时（send 的 timeout_ms 另行约束读写）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// ACK 字节数（0x01 = 应用层已收）。
const ACK: u8 = 0x01;

/// 上层接收回调（FFI 侧适配 UniFFI callback interface）。
pub trait NodeSink: Send + Sync {
    /// 收到一条消息。from_node_id_hex 为对端节点 id（64 位小写 hex）。
    fn on_message(&self, from_node_id_hex: String, payload: Vec<u8>);
    /// 端点就绪（绑定完成，地址快照可用）。进程生命周期内一次。
    fn on_ready(&self, node_id_hex: String, naddr: String);
}

/// 常驻节点。内部持有独立 tokio runtime（FFI 宿主线程非 async 上下文）。
pub struct Node {
    rt: tokio::runtime::Runtime,
    ep: Endpoint,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Node {
    /// 启动端点并派发接收循环。
    ///
    /// - `relay_url`：自建 iroh-relay URL；空 = RelayMode::Disabled（v9 默认）
    /// - `seed32`：节点密钥种子（ed25519 私钥字节）。由调用方生成并安全落盘，
    ///   重启沿用 → 节点 id 稳定，联系人侧 QR 快照长期有效
    pub fn start(relay_url: &str, seed32: &[u8; 32], cb: Arc<dyn NodeSink>) -> crate::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| crate::CoreError::Io(e.to_string()))?;
        let seed = *seed32;
        let relay = relay_url.trim().to_owned();
        // 中继 URL 先行解析（不放 bind 的 async 块里：错误类型不兼容 ? 转换）
        let builder = {
            let mut builder = Endpoint::builder(presets::Minimal).secret_key(SecretKey::from_bytes(&seed));
            builder = if relay.is_empty() {
                builder.relay_mode(RelayMode::Disabled)
            } else {
                let url: RelayUrl = relay
                    .parse()
                    .map_err(|e| crate::CoreError::Config(format!("relay url: {e}")))?;
                builder.relay_mode(RelayMode::custom([url]))
            };
            builder.alpns(vec![ALPN.to_vec()])
        };
        let ep = rt
            .block_on(builder.bind())
            .map_err(|e| crate::CoreError::Io(e.to_string()))?;

        cb.on_ready(hex(ep.id().as_bytes()), naddr_string(&ep, false));

        // 接收循环：accept → 每连接一个任务 → 每流一条消息 → 回 ACK
        let cb = cb.clone();
        let ep2 = ep.clone();
        let accept_task = rt.spawn(async move {
            while let Some(incoming) = ep2.accept().await {
                let cb = cb.clone();
                tokio::spawn(async move {
                    let conn = match incoming.accept() {
                        Ok(accepting) => match accepting.await {
                            Ok(conn) => conn,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };
                    let remote = hex(conn.remote_id().as_bytes());
                    loop {
                        let (mut send, mut recv) = match conn.accept_bi().await {
                            Ok(pair) => pair,
                            Err(_) => return, // 对端关流/关连接
                        };
                        let payload = match recv.read_to_end(MAX_MSG_LEN).await {
                            Ok(bytes) => bytes,
                            Err(_) => return,
                        };
                        cb.on_message(remote.clone(), payload);
                        // 应用层已收：回 ACK（忽略写失败，连接即将关闭）
                        let _ = send.write_all(&[ACK]).await;
                        let _ = send.finish();
                    }
                });
            }
        });

        Ok(Self {
            rt,
            ep,
            accept_task: Mutex::new(Some(accept_task)),
        })
    }

    /// 本端节点 id（64 位小写 hex）。
    pub fn node_id_hex(&self) -> String {
        hex(self.ep.id().as_bytes())
    }

    /// 出示给联系人的地址快照（编码进 QR / 存联系人表）。
    pub fn export_naddr(&self) -> String {
        naddr_string(&self.ep, false)
    }

    /// 按快照发送一条消息。阻塞至对端应用层确认或失败（调用方放在 IO 线程）。
    pub fn send(&self, naddr: &str, payload: &[u8], timeout_ms: u64) -> crate::Result<()> {
        let addr = parse_naddr(naddr)?;
        if payload.is_empty() {
            return Err(crate::CoreError::Config("empty payload".into()));
        }
        if payload.len() > MAX_MSG_LEN {
            return Err(crate::CoreError::Config(format!(
                "payload {} exceeds {}",
                payload.len(),
                MAX_MSG_LEN
            )));
        }
        let ep = self.ep.clone();
        let payload = payload.to_vec();
        self.rt.block_on(async move {
            let _ = tokio::time::timeout(CONNECT_TIMEOUT, ep.online()).await; // 尽力等待本地网络就绪，不阻塞结果
            let conn = tokio::time::timeout(Duration::from_millis(timeout_ms), ep.connect(addr, ALPN))
                .await
                .map_err(|_| crate::CoreError::Io("connect timeout".into()))?
                .map_err(|e| crate::CoreError::Io(format!("connect: {e}")))?;
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| crate::CoreError::Io(format!("open_bi: {e}")))?;
            send.write_all(&payload)
                .await
                .map_err(|e| crate::CoreError::Io(format!("write: {e}")))?;
            send.finish()
                .map_err(|e| crate::CoreError::Io(format!("finish: {e}")))?;
            // 等 ACK = 对端应用层已收
            let ack = tokio::time::timeout(Duration::from_millis(timeout_ms), recv.read_to_end(1))
                .await
                .map_err(|_| crate::CoreError::Io("ack timeout".into()))?
                .map_err(|e| crate::CoreError::Io(format!("ack read: {e}")))?;
            if ack != [ACK] {
                return Err(crate::CoreError::Io("ack missing".into()));
            }
            Ok(())
        })
    }

    /// 停止：关端点、回收接收循环。Node 随后可丢弃（runtime 一并撤除）。
    pub fn stop(&self) {
        if let Some(task) = self.accept_task.lock().unwrap().take() {
            task.abort();
        }
        let ep = self.ep.clone();
        let _ = self.rt.block_on(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), ep.close()).await;
        });
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------- dc://node 快照编解码 ----------------

/// 编码：`dc://node?v=1&id=<hex>[&a=<b64url(sockaddr)>,...][&r=<b64url(relay url)>]`
/// sockaddr 字节 = v4: 4+2 / v6: 16+2（octets + 大端 port）；无直连地址时省略 a。
/// 测试（同进程环回互发）走 `include_loopback=true`。
pub fn naddr_string(ep: &Endpoint, include_loopback: bool) -> String {
    let addr = ep.addr();
    let mut out = format!("dc://node?v=1&id={}", hex(addr.id.as_bytes()));
    let ips: Vec<String> = addr
        .ip_addrs()
        .filter(|a| !a.ip().is_unspecified() && (include_loopback || !a.ip().is_loopback()))
        .map(|a| b64(&sockaddr_bytes(a)))
        .collect();
    if !ips.is_empty() {
        out.push_str("&a=");
        out.push_str(&ips.join(","));
    }
    if let Some(relay) = addr.relay_urls().next() {
        out.push_str("&r=");
        out.push_str(&b64(relay.as_str().as_bytes()));
    }
    out
}

/// 从快照解析 EndpointAddr（send 用）。
pub fn parse_naddr(s: &str) -> crate::Result<EndpointAddr> {
    let body = s
        .strip_prefix("dc://node?")
        .ok_or_else(|| crate::CoreError::Config("not a dc://node snapshot".into()))?;
    let mut id: Option<EndpointId> = None;
    let mut addrs = Vec::new();
    for pair in body.split('&') {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| crate::CoreError::Config("bad snapshot pair".into()))?;
        match k {
            "v" if v != "1" => {
                return Err(crate::CoreError::Config("unsupported snapshot version".into()));
            }
            "v" => {}
            "id" => {
                let bytes = unhex(v).ok_or_else(|| crate::CoreError::Config("bad node id".into()))?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::CoreError::Config("node id must be 32 bytes".into()))?;
                id = Some(
                    EndpointId::from_bytes(&arr).map_err(|e| crate::CoreError::Config(format!("node id: {e}")))?,
                );
            }
            "a" => {
                for part in v.split(',') {
                    addrs.push(TransportAddr::Ip(sockaddr_from_bytes(&unb64(part)?)?));
                }
            }
            "r" => {
                let url = String::from_utf8(unb64(v)?)
                    .map_err(|_| crate::CoreError::Config("bad relay url".into()))?;
                let relay: RelayUrl = url
                    .parse()
                    .map_err(|e| crate::CoreError::Config(format!("relay url: {e}")))?;
                addrs.push(TransportAddr::Relay(relay));
            }
            _ => {} // 未知字段忽略（向前兼容）
        }
    }
    let id = id.ok_or_else(|| crate::CoreError::Config("snapshot missing id".into()))?;
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// 快照 → 节点 id hex（Kotlin 存联系人表用）。
pub fn node_id_of_naddr(s: &str) -> crate::Result<String> {
    Ok(hex(parse_naddr(s)?.id.as_bytes()))
}

fn sockaddr_bytes(a: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    match a {
        SocketAddr::V4(v4) => {
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

fn sockaddr_from_bytes(bytes: &[u8]) -> crate::Result<SocketAddr> {
    match bytes.len() {
        6 => Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
        ))),
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                0,
                0,
            )))
        }
        _ => Err(crate::CoreError::Config("bad sockaddr bytes".into())),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// base64url 无填充编码（与 Kotlin `getUrlEncoder().withoutPadding()` 对齐）。
fn b64(bytes: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TBL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TBL[n as usize & 63] as char);
        }
    }
    out
}

/// base64url 无填充解码（[b64] 的逆）。
fn unb64(s: &str) -> crate::Result<Vec<u8>> {
    fn rev(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    if s.len() % 4 == 1 {
        return Err(crate::CoreError::Config("bad base64 length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s.as_bytes() {
        acc = (acc << 6) | rev(c).ok_or_else(|| crate::CoreError::Config("bad base64 char".into()))?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    struct Sink(mpsc::Sender<(String, Vec<u8>)>);
    impl NodeSink for Sink {
        fn on_message(&self, from: String, payload: Vec<u8>) {
            let _ = self.0.send((from, payload));
        }
        fn on_ready(&self, _: String, _: String) {}
    }

    fn seed(n: u8) -> [u8; 32] {
        let mut s = [n; 32];
        s[31] = n.wrapping_add(1);
        s
    }

    #[test]
    fn sockaddr_roundtrip() {
        for a in [
            "192.168.1.7:43210".parse::<SocketAddr>().unwrap(),
            "10.0.0.2:65535".parse::<SocketAddr>().unwrap(),
            "[::1]:8080".parse::<SocketAddr>().unwrap(),
            "[2001:db8::5]:443".parse::<SocketAddr>().unwrap(),
        ] {
            assert_eq!(a, sockaddr_from_bytes(&sockaddr_bytes(&a)).unwrap());
        }
        assert!(sockaddr_from_bytes(&[0u8; 5]).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for sample in [
            &b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
            &sockaddr_bytes(&"192.168.1.7:43210".parse().unwrap()),
        ] {
            assert_eq!(sample.to_vec(), unb64(&b64(sample)).unwrap());
        }
        assert!(unb64("A").is_err());
        assert!(unb64("AB#C").is_err());
    }

    #[test]
    fn naddr_parse_rejects_garbage() {
        assert!(parse_naddr("").is_err());
        assert!(parse_naddr("https://x").is_err());
        assert!(parse_naddr("dc://node?v=1").is_err()); // 缺 id
        assert!(parse_naddr("dc://node?v=2&id=00").is_err()); // 版本不符
        assert!(parse_naddr(&format!("dc://node?v=1&id={}", "ab".repeat(31))).is_err()); // id 短
    }

    #[test]
    fn naddr_roundtrip_via_runtime() {
        let (tx, _) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
        let n = Node::start("", &seed(7), Arc::new(Sink(tx))).unwrap();
        let snap = naddr_string(&n.ep, true);
        let addr = parse_naddr(&snap).unwrap();
        assert_eq!(addr.id.as_bytes(), n.ep.id().as_bytes());
        assert!(addr.ip_addrs().next().is_some() || addr.relay_urls().next().is_some());
        assert_eq!(node_id_of_naddr(&snap).unwrap(), n.node_id_hex());
        n.stop();
    }

    #[test]
    fn two_nodes_exchange_message() {
        let (tx, rx) = mpsc::channel();
        let a = Node::start("", &seed(1), Arc::new(Sink(tx.clone()))).unwrap();
        let b = Node::start("", &seed(2), Arc::new(Sink(tx.clone()))).unwrap();

        // 含环回的测试快照：同进程直连 localhost
        let naddr_b = naddr_string(&b.ep, true);
        a.send(&naddr_b, b"ping-payload", 15_000).expect("send");

        // B 收到 A 的消息：on_message 的 remote 是对端（A）的节点 id
        let a_id = a.node_id_hex();
        let (from, payload) = rx.recv_timeout(Duration::from_secs(15)).expect("recv");
        assert_eq!(from, a_id);
        assert_eq!(payload, b"ping-payload");

        a.stop();
        b.stop();
    }

    #[test]
    fn send_rejects_bad_input() {
        let (tx, _) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
        let n = Node::start("", &seed(3), Arc::new(Sink(tx))).unwrap();
        assert!(n.send("garbage", b"x", 1000).is_err());
        assert!(n.send("dc://node?v=1&id=00", b"x", 1000).is_err()); // id 非法
        let snap = naddr_string(&n.ep, true);
        assert!(n.send(&snap, &[], 1000).is_err()); // 空载荷
        assert!(n.send(&snap, &vec![0u8; MAX_MSG_LEN + 1], 1000).is_err());
        n.stop();
    }

    /// 未经显式 stop 的 Node 丢弃也安全（Drop 内部 stop）。
    #[test]
    fn drop_without_stop_is_safe() {
        let (tx, _rx) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
        let _n = Node::start("", &seed(4), Arc::new(Sink(tx))).unwrap();
    }
}
