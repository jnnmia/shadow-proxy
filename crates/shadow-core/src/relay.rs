//! ghost-core/relay: 本地透明代理中继监听与双向数据流转发

use crate::protocol::{self, TargetAddr};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("协议解析错误: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("上游代理连接失败: {0}")]
    UpstreamConnect(String),
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
}

/// 本地中继服务
pub struct RelayServer {
    config: RelayConfig,
    stats: Arc<TrafficStats>,
}

pub struct BoundRelayServer {
    config: RelayConfig,
    listener: TcpListener,
    stats: Arc<TrafficStats>,
    local_addr: SocketAddr,
}

impl BoundRelayServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> Arc<TrafficStats> {
        Arc::clone(&self.stats)
    }

    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        tracing::info!("本地透明中继服务已启动，监听地址: {}", self.local_addr);

        loop {
            tokio::select! {
                res = self.listener.accept() => {
                    let (inbound, client_addr) = res?;
                    let config = self.config.clone();
                    let stats = Arc::clone(&self.stats);

                    tokio::spawn(async move {
                        if let Err(e) = handle_inbound_connection(inbound, config, stats).await {
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
        Self {
            config,
            stats: Arc::new(TrafficStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<TrafficStats> {
        Arc::clone(&self.stats)
    }

    pub async fn bind(config: RelayConfig) -> Result<BoundRelayServer> {
        Self::bind_with_stats(config, Arc::new(TrafficStats::default())).await
    }

    pub async fn bind_with_stats(
        config: RelayConfig,
        stats: Arc<TrafficStats>,
    ) -> Result<BoundRelayServer> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(BoundRelayServer {
            config,
            listener,
            stats,
            local_addr,
        })
    }

    /// 启动本地中继监听，支持通过广播信号优雅停机
    pub async fn run(&self, shutdown: broadcast::Receiver<()>) -> Result<()> {
        let bound = Self::bind_with_stats(self.config.clone(), Arc::clone(&self.stats)).await?;
        bound.run(shutdown).await
    }
}

/// 处理单条被劫持连接：读取目标地址，向 SOCKS5 上游发起隧道，执行双向拷贝
async fn handle_inbound_connection(
    mut inbound: TcpStream,
    config: RelayConfig,
    stats: Arc<TrafficStats>,
) -> Result<()> {
    // 1. 读取本地透明代理帧头（由 ghost-hook 在 connect 拦截时打入）
    let target = TargetAddr::decode(&mut inbound).await?;
    tracing::info!("捕获重定向流量 -> 实际目标: {:?}", target);

    // 2. 连接至上游 SOCKS5 代理
    let mut upstream = TcpStream::connect(config.upstream_proxy)
        .await
        .map_err(|e| RelayError::UpstreamConnect(format!("{}: {}", config.upstream_proxy, e)))?;

    // 3. 执行标准 SOCKS5 协议握手
    let auth = config.proxy_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    protocol::socks5_connect(&mut upstream, &target, auth).await?;
    tracing::debug!("已向上游代理建立目标通道: {:?}", target);

    // 4. 双向零拷贝数据流动 (使用 tokio 内置双向流传输)
    match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
        Ok((from_client, from_server)) => {
            stats.bytes_sent.fetch_add(from_client, Ordering::Relaxed);
            stats.bytes_received.fetch_add(from_server, Ordering::Relaxed);
            Ok(())
        }
        Err(e) => Err(RelayError::Io(e)),
    }
}
