//! shadow-core/relay: 本地透明代理中继监听、智能分流与双向数据流转发

use crate::protocol::{self, InboundHeader, TargetAddr};
use crate::router::{RouteAction, Router};
use crate::session::{SessionStatus, SessionTracker};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("协议解析错误: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("上游代理连接失败: {0}")]
    UpstreamConnect(String),
    #[error("直连目标失败: {0}")]
    DirectConnect(String),
}

pub type Result<T> = std::result::Result<T, RelayError>;

/// 实时流量统计计数器
#[derive(Default, Debug)]
pub struct TrafficStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

/// 本地透明代理中继配置
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub upstream_proxy: SocketAddr,
    pub proxy_auth: Option<(String, String)>,
    pub strict_dns: bool,
    pub dns_over_tcp_server: Option<SocketAddr>,
    pub handshake_timeout: Option<Duration>,
    pub upstream_is_http: bool,
}

/// 本地中继服务
pub struct RelayServer {
    config: RelayConfig,
    stats: Arc<TrafficStats>,
    router: Arc<RwLock<Router>>,
    tracker: Arc<SessionTracker>,
}

pub struct BoundRelayServer {
    config: RelayConfig,
    listener: TcpListener,
    stats: Arc<TrafficStats>,
    router: Arc<RwLock<Router>>,
    tracker: Arc<SessionTracker>,
    local_addr: SocketAddr,
}

impl BoundRelayServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> Arc<TrafficStats> {
        Arc::clone(&self.stats)
    }

    pub fn router(&self) -> Arc<RwLock<Router>> {
        Arc::clone(&self.router)
    }

    pub fn tracker(&self) -> Arc<SessionTracker> {
        Arc::clone(&self.tracker)
    }

    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        tracing::info!("本地透明中继服务已启动，监听地址: {}", self.local_addr);

        loop {
            tokio::select! {
                res = self.listener.accept() => {
                    let (inbound, client_addr) = match res {
                        Ok(conn) => conn,
                        Err(e) => {
                            // 关键修复：系统休眠/挂起唤醒时，Windows 网络栈可能抛出瞬态错误
                            // 绝不能直接退出 run() 循环导致中继永久死锁，需记录日志并平稳重试恢复
                            tracing::warn!("本地透明中继 accept 遇到瞬态错误 (休眠唤醒或网络栈抖动): {}，正在恢复监听...", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let _ = inbound.set_nodelay(true);
                    let config = self.config.clone();
                    let stats = Arc::clone(&self.stats);
                    let router = Arc::clone(&self.router);
                    let tracker = Arc::clone(&self.tracker);

                    tokio::spawn(async move {
                        if let Err(e) = handle_inbound_connection(inbound, config, stats, router, tracker).await {
                            tracing::warn!("客户端 [{}] 连接处理异常: {}", client_addr, e);
                        }
                    });
                }
                _ = shutdown.recv() => {
                    tracing::info!("收到终止信号，本地透明中继平稳停止");
                    break;
                }
            }
        }
        Ok(())
    }
}

impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self::with_router_and_tracker(
            config,
            Arc::new(RwLock::new(Router::default())),
            Arc::new(SessionTracker::default()),
        )
    }

    pub fn with_router_and_tracker(
        config: RelayConfig,
        router: Arc<RwLock<Router>>,
        tracker: Arc<SessionTracker>,
    ) -> Self {
        Self {
            config,
            stats: Arc::new(TrafficStats::default()),
            router,
            tracker,
        }
    }

    pub fn stats(&self) -> Arc<TrafficStats> {
        Arc::clone(&self.stats)
    }

    pub fn router(&self) -> Arc<RwLock<Router>> {
        Arc::clone(&self.router)
    }

    pub fn tracker(&self) -> Arc<SessionTracker> {
        Arc::clone(&self.tracker)
    }

    pub async fn bind(config: RelayConfig) -> Result<BoundRelayServer> {
        Self::bind_with_components(
            config,
            Arc::new(TrafficStats::default()),
            Arc::new(RwLock::new(Router::default())),
            Arc::new(SessionTracker::default()),
        )
        .await
    }

    pub async fn bind_with_stats(
        config: RelayConfig,
        stats: Arc<TrafficStats>,
    ) -> Result<BoundRelayServer> {
        Self::bind_with_components(
            config,
            stats,
            Arc::new(RwLock::new(Router::default())),
            Arc::new(SessionTracker::default()),
        )
        .await
    }

    pub async fn bind_with_components(
        config: RelayConfig,
        stats: Arc<TrafficStats>,
        router: Arc<RwLock<Router>>,
        tracker: Arc<SessionTracker>,
    ) -> Result<BoundRelayServer> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(BoundRelayServer {
            config,
            listener,
            stats,
            router,
            tracker,
            local_addr,
        })
    }

    /// 启动本地中继监听，支持通过广播信号优雅停机
    pub async fn run(&self, shutdown: broadcast::Receiver<()>) -> Result<()> {
        let bound = Self::bind_with_components(
            self.config.clone(),
            Arc::clone(&self.stats),
            Arc::clone(&self.router),
            Arc::clone(&self.tracker),
        )
        .await?;
        bound.run(shutdown).await
    }
}

/// 高性能双向流量采样转发泵：在双向异步流之间转发数据，同时实时累加会话与全局上下行流量
pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    up_counter: &AtomicU64,
    down_counter: &AtomicU64,
    global_stats: &TrafficStats,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let client_to_server = async {
        let mut buf = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = a_read.read(&mut buf).await?;
            if n == 0 {
                let _ = b_write.shutdown().await;
                break;
            }
            b_write.write_all(&buf[..n]).await?;
            total += n as u64;
            up_counter.fetch_add(n as u64, Ordering::Relaxed);
            global_stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok::<u64, std::io::Error>(total)
    };

    let server_to_client = async {
        let mut buf = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = b_read.read(&mut buf).await?;
            if n == 0 {
                let _ = a_write.shutdown().await;
                break;
            }
            a_write.write_all(&buf[..n]).await?;
            total += n as u64;
            down_counter.fetch_add(n as u64, Ordering::Relaxed);
            global_stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok::<u64, std::io::Error>(total)
    };

    tokio::try_join!(client_to_server, server_to_client)
}

/// 处理单条被劫持连接：读取目标地址与发起进程，评估分流规则，执行 Direct / Proxy / Block
async fn handle_inbound_connection(
    mut inbound: TcpStream,
    config: RelayConfig,
    stats: Arc<TrafficStats>,
    router: Arc<RwLock<Router>>,
    tracker: Arc<SessionTracker>,
) -> Result<()> {
    let timeout_duration = config.handshake_timeout.unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT);

    // 1. 读取本地透明代理帧头（支持 v1 与 v2 自适应解码，超时防护防 Slowloris）
    let header = match timeout(timeout_duration, InboundHeader::decode(&mut inbound)).await {
        Ok(Ok(header)) => header,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "读取目标透明代理帧头握手超时",
            )));
        }
    };
    let target = header.target;
    let target_str = target.to_string();
    let pid = header.pid;
    let process_name = header.process_name;

    // 2. 路由分流引擎判定
    let decision = {
        let r = router.read().unwrap();
        r.eval_with_proc(&target, process_name.as_deref())
    };
    tracing::info!(
        "捕获连接 -> 目标: {} | 进程: {:?} (PID: {:?}) | 动作: {} | 命中规则: {}",
        target_str,
        process_name.as_deref().unwrap_or("未知"),
        pid.unwrap_or(0),
        decision.action,
        decision.rule_name
    );

    // 3. 处理阻断 (Block)
    if decision.action == RouteAction::Block {
        tracker.start_session_full(
            &target_str,
            &decision.rule_name,
            RouteAction::Block,
            true,
            pid,
            process_name,
        );
        tracing::warn!("规则阻断目标连接: {}", target_str);
        return Ok(()); // 立即断开连接
    }

    // 4. 创建活跃会话（返回实时原子累加计数器）
    let (session_id, up_counter, down_counter) = tracker.start_session_full(
        &target_str,
        &decision.rule_name,
        decision.action,
        false,
        pid,
        process_name,
    );

    // 5. 分支处理：直连 (Direct) vs 代理 (Proxy)
    match decision.action {
        RouteAction::Direct => {
            let connect_res = match &target {
                TargetAddr::Ip(sa) => timeout(timeout_duration, TcpStream::connect(*sa)).await,
                TargetAddr::Domain(host, port) => {
                    if config.strict_dns {
                        if let Some(dns_server) = config.dns_over_tcp_server {
                            match crate::dns::resolve_dns_over_tcp(dns_server, host.as_str(), timeout_duration).await {
                                Ok(ip) => {
                                    let sa = SocketAddr::new(ip, *port);
                                    timeout(timeout_duration, TcpStream::connect(sa)).await
                                }
                                Err(e) => {
                                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                                    return Err(RelayError::DirectConnect(format!(
                                        "{}:{}: 严格防泄漏模式下 DNS-over-TCP 解析失败: {}",
                                        host, port, e
                                    )));
                                }
                            }
                        } else {
                            tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                            return Err(RelayError::DirectConnect(format!(
                                "{}:{}: 严格防泄漏模式下禁止通过宿主系统 DNS 解析直连域名，必须经由安全代理通道或配置 DNS-over-TCP",
                                host, port
                            )));
                        }
                    } else {
                        timeout(timeout_duration, TcpStream::connect((host.as_str(), *port))).await
                    }
                }
            };

            let mut outbound = match connect_res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::DirectConnect(format!("{}: {}", target_str, e)));
                }
                Err(_) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::DirectConnect(format!("{}: 直连目标超时", target_str)));
                }
            };

            let _ = outbound.set_nodelay(true);
            match copy_bidirectional_with_stats(&mut inbound, &mut outbound, &up_counter, &down_counter, &stats).await {
                Ok((from_client, from_server)) => {
                    tracker.finish_session(session_id, SessionStatus::Closed, from_client, from_server);
                    Ok(())
                }
                Err(e) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    Err(RelayError::Io(e))
                }
            }
        }
        RouteAction::Proxy => {
            let mut upstream = match timeout(timeout_duration, TcpStream::connect(config.upstream_proxy)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::UpstreamConnect(format!("{}: {}", config.upstream_proxy, e)));
                }
                Err(_) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::UpstreamConnect(format!("{}: 连接上游代理超时", config.upstream_proxy)));
                }
            };

            let auth = config.proxy_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            if config.upstream_is_http {
                if let Err(e) = timeout(timeout_duration, protocol::http_connect(&mut upstream, &target, auth)).await {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::UpstreamConnect(format!("上游 HTTP CONNECT 握手超时或失败: {}", e)));
                }
            } else {
                if let Err(e) = timeout(timeout_duration, protocol::socks5_connect(&mut upstream, &target, auth)).await {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    return Err(RelayError::UpstreamConnect(format!("上游 SOCKS5 握手超时或失败: {}", e)));
                }
            }

            let _ = upstream.set_nodelay(true);
            match copy_bidirectional_with_stats(&mut inbound, &mut upstream, &up_counter, &down_counter, &stats).await {
                Ok((from_client, from_server)) => {
                    tracker.finish_session(session_id, SessionStatus::Closed, from_client, from_server);
                    Ok(())
                }
                Err(e) => {
                    tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                    Err(RelayError::Io(e))
                }
            }
        }
        RouteAction::Block => unreachable!(),
    }
}
