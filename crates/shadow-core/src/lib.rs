//! ghost-core: SOCKS5/HTTP 异步传输、DNS 严格防泄漏与流量中继引擎

pub mod protocol;
pub mod relay;
pub mod router;
pub mod session;

pub use protocol::{ProtocolError, TargetAddr};
pub use relay::{BoundRelayServer, RelayConfig, RelayError, RelayServer, TrafficStats};
pub use router::{RouteAction, RouteDecision, RuleItem, RulePattern, Router};
pub use session::{SessionRecord, SessionStatus, SessionTracker};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("协议错误: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("中继错误: {0}")]
    Relay(#[from] relay::RelayError),
    #[error("DNS 解析被严格策略阻断: {0}")]
    DnsBlocked(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_target_addr_ipv4_codec() {
        let addr = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 100),
            8080,
        )));
        let encoded = addr.encode();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = TargetAddr::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, decoded);
    }

    #[tokio::test]
    async fn test_target_addr_domain_codec() {
        let addr = TargetAddr::Domain("example.com".into(), 443);
        let encoded = addr.encode();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = TargetAddr::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, decoded);
    }

    #[tokio::test]
    async fn test_target_addr_ipv6_codec() {
        let addr = TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            9000,
            0,
            0,
        )));
        let encoded = addr.encode();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = TargetAddr::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, decoded);
    }

    #[tokio::test]
    async fn test_target_addr_invalid_magic_adversarial() {
        let mut invalid_buf = b"FAKE\x01\x7f\x00\x00\x01\x00\x50".to_vec();
        let mut cursor = std::io::Cursor::new(&mut invalid_buf);
        let err = TargetAddr::decode(&mut cursor).await.unwrap_err();
        match err {
            ProtocolError::InvalidMagic(m) => assert_eq!(&m, b"FAKE"),
            _ => panic!("预期 InvalidMagic，实际返回: {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_mock_socks5_connect_success() {
        // 启动 Mock SOCKS5 服务端
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // 1. 握手阶段: 读取 VER + NMETHODS + METHODS
            let mut buf = [0u8; 3];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05); // VER=5
            socket.write_all(&[0x05, 0x00]).await.unwrap(); // VER=5, METHOD=NO_AUTH

            // 2. CONNECT 请求阶段: 读取 [0x05, 0x01, 0x00, 0x01, IPv4(4), Port(2)]
            let mut req = [0u8; 10];
            socket.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x01); // CONNECT

            // 3. 应答成功: [0x05, 0x00, 0x00, 0x01, 0x7f, 0, 0, 1, 0x04, 0x00]
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x00]).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let target = TargetAddr::Ip("127.0.0.1:80".parse().unwrap());
        protocol::socks5_connect(&mut client, &target, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_socks5_connect_server_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            socket.read_exact(&mut req).await.unwrap();
            // 返回目标拒绝连接错误 0x05
            socket.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let target = TargetAddr::Ip("1.1.1.1:53".parse().unwrap());
        let err = protocol::socks5_connect(&mut client, &target, None).await.unwrap_err();
        assert!(err.to_string().contains("目标连接被拒绝"), "错误信息: {}", err);
    }

    #[tokio::test]
    async fn test_full_relay_roundtrip() {
        // 1. 目标回显服务端 (Echo Target)
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"WORLD").await.unwrap();
        });

        // 2. Mock 上游 SOCKS5 服务端
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = socks_listener.accept().await.unwrap();
            let mut handshake = [0u8; 3];
            s.read_exact(&mut handshake).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x00]).await.unwrap();

            // SOCKS5 隧道建立后，连接至真实 Echo 服务端
            let echo_conn = TcpStream::connect(echo_addr).await.unwrap();
            let (mut sr, mut sw) = s.into_split();
            let (mut er, mut ew) = echo_conn.into_split();
            let _ = tokio::join!(tokio::io::copy(&mut sr, &mut ew), tokio::io::copy(&mut er, &mut sw));
        });

        // 3. 启动本地中继服务
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        drop(relay_listener); // 释放端口供 RelayServer 使用

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let relay_server = RelayServer::new(RelayConfig {
            listen_addr: relay_addr,
            upstream_proxy: socks_addr,
            proxy_auth: None,
            strict_dns: true,
            handshake_timeout: None,
        });

        let stats = relay_server.stats();
        tokio::spawn(async move {
            let _ = relay_server.run(shutdown_rx).await;
        });

        // 等待中继就绪
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 4. 模拟被 Hook 进程向本地中继发起连接
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        // 发送重定向帧头
        let target = TargetAddr::Ip(echo_addr);
        client.write_all(&target.encode()).await.unwrap();

        // 发送业务数据
        client.write_all(b"HELLO").await.unwrap();
        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"WORLD");

        client.shutdown().await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed) >= 5);
        assert!(stats.bytes_received.load(std::sync::atomic::Ordering::Relaxed) >= 5);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_relay_direct_route_roundtrip() {
        // 1. 直连目标服务端 (Echo Direct Target)
        let direct_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = direct_listener.accept().await.unwrap();
            let mut buf = [0u8; 6];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"DIRECT").await.unwrap();
        });

        // 2. 启动中继，配置全直连规则
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        drop(relay_listener);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let router = Arc::new(std::sync::RwLock::new(Router::preset_direct_all()));
        let tracker = Arc::new(SessionTracker::default());

        let relay_server = RelayServer::with_router_and_tracker(
            RelayConfig {
                listen_addr: relay_addr,
                upstream_proxy: "127.0.0.1:9".parse().unwrap(), // 无效代理地址，直连不应访问它
                proxy_auth: None,
                strict_dns: true,
                handshake_timeout: None,
            },
            router,
            Arc::clone(&tracker),
        );

        tokio::spawn(async move {
            let _ = relay_server.run(shutdown_rx).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 3. 客户端发送数据，验证直连成功
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let target = TargetAddr::Ip(direct_addr);
        client.write_all(&target.encode()).await.unwrap();
        client.write_all(b"PINGGG").await.unwrap();

        let mut res = [0u8; 6];
        client.read_exact(&mut res).await.unwrap();
        assert_eq!(&res, b"DIRECT");

        client.shutdown().await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let sessions = tracker.list_sessions(5);
        assert!(!sessions.is_empty());
        assert_eq!(sessions[0].action, RouteAction::Direct);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_relay_block_route() {
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        drop(relay_listener);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let mut r = Router::preset_direct_all();
        r.add_rule(RuleItem {
            id: "block-8888".into(),
            name: "阻断 8888 端口".into(),
            pattern: RulePattern::Port(8888),
            action: RouteAction::Block,
            enabled: true,
        });

        let tracker = Arc::new(SessionTracker::default());
        let relay_server = RelayServer::with_router_and_tracker(
            RelayConfig {
                listen_addr: relay_addr,
                upstream_proxy: "127.0.0.1:9".parse().unwrap(),
                proxy_auth: None,
                strict_dns: true,
                handshake_timeout: None,
            },
            Arc::new(std::sync::RwLock::new(r)),
            Arc::clone(&tracker),
        );

        tokio::spawn(async move {
            let _ = relay_server.run(shutdown_rx).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let target = TargetAddr::Ip("127.0.0.1:8888".parse().unwrap());
        client.write_all(&target.encode()).await.unwrap();

        // 验证连接立即被关闭（读取返回 0 字节 EOF）
        let mut buf = [0u8; 10];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "被阻断连接应当直接关闭");

        let sessions = tracker.list_sessions(5);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].status, SessionStatus::Blocked);
        assert_eq!(sessions[0].action, RouteAction::Block);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_relay_slowloris_handshake_timeout() {
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        drop(relay_listener);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let tracker = Arc::new(SessionTracker::default());

        // 设置极短的 100ms 握手超时以验证防御 Slowloris 慢速拒绝服务
        let relay_server = RelayServer::with_router_and_tracker(
            RelayConfig {
                listen_addr: relay_addr,
                upstream_proxy: "127.0.0.1:9".parse().unwrap(),
                proxy_auth: None,
                strict_dns: true,
                handshake_timeout: Some(tokio::time::Duration::from_millis(100)),
            },
            Arc::new(std::sync::RwLock::new(Router::preset_direct_all())),
            Arc::clone(&tracker),
        );

        tokio::spawn(async move {
            let _ = relay_server.run(shutdown_rx).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 客户端连接后不发送任何数据
        let mut client = TcpStream::connect(relay_addr).await.unwrap();

        // 等待超过 100ms 超时时间
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // 预期服务端已因握手超时主动关闭连接 (读取返回 0 EOF)
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "慢速无数据连接在超时后必须被服务端强制关闭");

        let _ = shutdown_tx.send(());
    }
}
