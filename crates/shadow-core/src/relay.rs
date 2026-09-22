//! shadow-core/relay: 本地透明代理中继监听、智能分流与双向数据流转发

use crate::protocol::{self, TargetAddr};
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
    pub handshake_timeout: Option<Duration>,
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
                    let (inbound, client_addr) = res?;
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

/// 处理单条被劫持连接：读取目标地址，评估分流规则，执行 Direct / Proxy / Block
async fn handle_inbound_connection(
    mut inbound: TcpStream,
    config: RelayConfig,
    stats: Arc<TrafficStats>,
    router: Arc<RwLock<Router>>,
    tracker: Arc<SessionTracker>,
) -> Result<()> {
    let timeout_duration = config.handshake_timeout.unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT);

    // 1. 读取本地透明代理帧头（由 shadow-hook 在 connect 拦截时打入，超时防护防 Slowloris）
    let target = match timeout(timeout_duration, TargetAddr::decode(&mut inbound)).await {
        Ok(Ok(target)) => target,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "读取目标透明代理帧头握手超时",
            )));
        }
    };
    let target_str = target.to_string();

    // 2. 路由分流引擎判定
    let decision = {
        let r = router.read().unwrap();
        r.eval(&target)
    };
    tracing::info!(
        "捕获连接 -> 目标: {} | 动作: {} | 命中规则: {}",
        target_str,
        decision.action,
        decision.rule_name
    );

    // 3. 处理阻断 (Block)
    if decision.action == RouteAction::Block {
        tracker.start_session(&target_str, &decision.rule_name, RouteAction::Block, true);
        tracing::warn!("规则阻断目标连接: {}", target_str);
        return Ok(()); // 立即断开连接
    }

    // 4. 创建活跃会话
    let session_id = tracker.start_session(
        &target_str,
        &decision.rule_name,
        decision.action,
        false,
    );

    // 5. 分支处理：直连 (Direct) vs 代理 (Proxy)
    match decision.action {
        RouteAction::Direct => {
            let connect_res = match &target {
                TargetAddr::Ip(sa) => timeout(timeout_duration, TcpStream::connect(*sa)).await,
                TargetAddr::Domain(host, port) => {
                    timeout(timeout_duration, TcpStream::connect((host.as_str(), *port))).await
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

            match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                Ok((from_client, from_server)) => {
                    stats.bytes_sent.fetch_add(from_client, Ordering::Relaxed);
                    stats.bytes_received.fetch_add(from_server, Ordering::Relaxed);
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
            if let Err(e) = timeout(timeout_duration, protocol::socks5_connect(&mut upstream, &target, auth)).await {
                tracker.finish_session(session_id, SessionStatus::Failed, 0, 0);
                return Err(RelayError::UpstreamConnect(format!("上游 SOCKS5 握手超时或失败: {}", e)));
            }

            match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
                Ok((from_client, from_server)) => {
                    stats.bytes_sent.fetch_add(from_client, Ordering::Relaxed);
                    stats.bytes_received.fetch_add(from_server, Ordering::Relaxed);
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
