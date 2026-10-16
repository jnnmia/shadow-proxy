//! ghost-core/protocol: 本地中继帧头与上游 SOCKS5 协议实现

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const GHOST_MAGIC: [u8; 4] = *b"GHST";
pub const SHADOW_MAGIC: [u8; 4] = *b"SHAD";
pub const MAX_DOMAIN_LEN: usize = 255;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("无效的魔数包头: {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("不支持的地址类型: {0}")]
    UnsupportedAddressType(u8),
    #[error("域名长度超过限制: {0}")]
    DomainTooLong(usize),
    #[error("无效的 UTF-8 域名: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("SOCKS5 协议错误: {0}")]
    Socks5(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// 目标地址抽象（支持 IPv4 / IPv6 / 域名）
#[derive(Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl fmt::Debug for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
            TargetAddr::Domain(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// 目标地址负载编码辅助函数
fn encode_target_payload(target: &TargetAddr, buf: &mut Vec<u8>) {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(host, port) => {
            buf.push(0x03);
            let host_bytes = host.as_bytes();
            let len = host_bytes.len().min(MAX_DOMAIN_LEN) as u8;
            buf.push(len);
            buf.extend_from_slice(&host_bytes[..len as usize]);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// 目标地址解码辅助函数
async fn decode_target_address<R: AsyncRead + Unpin>(reader: &mut R, addr_type: u8) -> Result<TargetAddr> {
    match addr_type {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            reader.read_exact(&mut ip_bytes).await?;
            let port = reader.read_u16().await?;
            let ip = Ipv4Addr::from(ip_bytes);
            Ok(TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))))
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            reader.read_exact(&mut ip_bytes).await?;
            let port = reader.read_u16().await?;
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
        }
        0x03 => {
            let len = reader.read_u8().await? as usize;
            if len == 0 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "目标域名长度不能为 0",
                )));
            }
            let mut host_bytes = vec![0u8; len];
            reader.read_exact(&mut host_bytes).await?;
            let port = reader.read_u16().await?;
            let host = String::from_utf8(host_bytes)?;
            if host.chars().any(|c| c.is_control() || c == ' ') {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "目标域名包含非法控制字符或空格",
                )));
            }
            Ok(TargetAddr::Domain(host, port))
        }
        other => Err(ProtocolError::UnsupportedAddressType(other)),
    }
}

/// 本地中继帧解析结果（包含目标地址与发起进程元数据）
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InboundHeader {
    pub target: TargetAddr,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

impl InboundHeader {
    pub fn new(target: TargetAddr, pid: Option<u32>, process_name: Option<String>) -> Self {
        Self {
            target,
            pid,
            process_name,
        }
    }

    /// 编码为本地中继帧 v2 格式：
    /// [4 字节 MAGIC: "SHAD"]
    /// [1 字节 版本号: 0x02]
    /// [4 字节 PID (Big Endian)]
    /// [1 字节 进程名长度 N (0..=64)]
    /// [N 字节 进程名 UTF-8]
    /// [目标地址 payload...]
    pub fn encode_v2(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&SHADOW_MAGIC);
        buf.push(0x02);
        buf.extend_from_slice(&self.pid.unwrap_or(0).to_be_bytes());

        let name = self.process_name.as_deref().unwrap_or("");
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(64) as u8;
        buf.push(name_len);
        if name_len > 0 {
            buf.extend_from_slice(&name_bytes[..name_len as usize]);
        }

        encode_target_payload(&self.target, &mut buf);
        buf
    }

    /// 编码为本地中继帧 v1 格式（向前兼容）：
    /// [4 字节 MAGIC: "GHST"]
    /// [目标地址 payload...]
    pub fn encode_v1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&GHOST_MAGIC);
        encode_target_payload(&self.target, &mut buf);
        buf
    }

    /// 从异步流中自适应解码本地中继帧头（自动兼容 v1 与 v2）
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        if magic != GHOST_MAGIC && magic != SHADOW_MAGIC {
            return Err(ProtocolError::InvalidMagic(magic));
        }

        let first_byte = reader.read_u8().await?;
        if first_byte == 0x02 {
            // Version 2 协议格式
            let pid = reader.read_u32().await?;
            let proc_len = reader.read_u8().await? as usize;
            let process_name = if proc_len > 0 {
                let mut proc_bytes = vec![0u8; proc_len];
                reader.read_exact(&mut proc_bytes).await?;
                String::from_utf8(proc_bytes).ok()
            } else {
                None
            };

            let addr_type = reader.read_u8().await?;
            let target = decode_target_address(reader, addr_type).await?;
            Ok(InboundHeader {
                target,
                pid: Some(pid),
                process_name,
            })
        } else {
            // Version 1 协议格式（first_byte 即为地址类型 0x01, 0x03, 0x04）
            let target = decode_target_address(reader, first_byte).await?;
            Ok(InboundHeader {
                target,
                pid: None,
                process_name: None,
            })
        }
    }
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    /// 默认编码为本地中继帧格式（向后兼容 v1 格式）
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&GHOST_MAGIC);
        encode_target_payload(self, &mut buf);
        buf
    }

    /// 从异步流中解码本地中继帧头
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        InboundHeader::decode(reader).await.map(|h| h.target)
    }
}

/// 执行 SOCKS5 认证协商握手 (RFC 1928 / RFC 1929)
pub async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    match auth {
        Some((_user, _pass)) => {
            // 支持无认证 (0x00) 与用户名/密码认证 (0x02)
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        }
        None => {
            // 仅无认证
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }
    }
    stream.flush().await?;

    // 读取握手应答
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(ProtocolError::Socks5(format!("非 SOCKS5 协议版本: 0x{:02x}", resp[0])));
    }

    match resp[1] {
        0x00 => {
            // 无需认证
            Ok(())
        }
        0x02 => {
            // 用户名/密码认证 (RFC 1929)
            if let Some((user, pass)) = auth {
                let u_bytes = user.as_bytes();
                let p_bytes = pass.as_bytes();
                let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
                auth_req.push(0x01); // 认证子协商版本
                auth_req.push(u_bytes.len().min(255) as u8);
                auth_req.extend_from_slice(&u_bytes[..u_bytes.len().min(255)]);
                auth_req.push(p_bytes.len().min(255) as u8);
                auth_req.extend_from_slice(&p_bytes[..p_bytes.len().min(255)]);

                stream.write_all(&auth_req).await?;
                stream.flush().await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(ProtocolError::Socks5("SOCKS5 用户名/密码验证失败".into()));
                }
                Ok(())
            } else {
                Err(ProtocolError::Socks5("服务端要求认证但未提供凭据".into()))
            }
        }
        0xff => {
            Err(ProtocolError::Socks5("服务端拒绝了所有可用的认证方式".into()))
        }
        other => {
            Err(ProtocolError::Socks5(format!("不支持的认证类型: 0x{:02x}", other)))
        }
    }
}

/// 执行 SOCKS5 握手并连接至目标地址 (RFC 1928)
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &TargetAddr,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    // 1. 发送并完成认证协商
    socks5_handshake(stream, auth).await?;

    // 2. 发送 CONNECT 请求 (0x01)
    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV=0x00
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            req.push(0x01); // ATYP=IPv4
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            req.push(0x04); // ATYP=IPv6
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(host, port) => {
            req.push(0x03); // ATYP=Domain
            let host_bytes = host.as_bytes();
            let len = host_bytes.len().min(MAX_DOMAIN_LEN) as u8;
            req.push(len);
            req.extend_from_slice(&host_bytes[..len as usize]);
            req.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&req).await?;
    stream.flush().await?;

    // 3. 读取 CONNECT 应答
    let mut reply_header = [0u8; 4];
    stream.read_exact(&mut reply_header).await?;
    if reply_header[0] != 0x05 {
        return Err(ProtocolError::Socks5("CONNECT 响应版本无效".into()));
    }
    if reply_header[1] != 0x00 {
        return Err(ProtocolError::Socks5(match reply_header[1] {
            0x01 => "SOCKS5 服务端常规失败 (0x01)".into(),
            0x02 => "连接被规则集阻断 (0x02)".into(),
            0x03 => "网络不可达 (0x03)".into(),
            0x04 => "主机不可达 (0x04)".into(),
            0x05 => "目标连接被拒绝 (0x05)".into(),
            0x06 => "TTL 超时 (0x06)".into(),
            0x07 => "不支持的命令 (0x07)".into(),
            0x08 => "不支持的地址类型 (0x08)".into(),
            code => format!("SOCKS5 未知错误代码: 0x{:02x}", code),
        }));
    }

    // 消耗应答中的 BND.ADDR 与 BND.PORT
    match reply_header[3] {
        0x01 => {
            let mut buf = [0u8; 4 + 2]; // 4 字节 IPv4 + 2 字节端口
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2]; // 16 字节 IPv6 + 2 字节端口
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len + 2]; // 域名 + 2 字节端口
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(ProtocolError::UnsupportedAddressType(other));
        }
    }

    Ok(())
}

/// 轻量 Base64 编码实现，避免引入外部依赖
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) & 63] as char);
        out.push(TABLE[(n >> 12) & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 执行 HTTP CONNECT 隧道代理握手 (RFC 7231 / RFC 2817)
pub async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &TargetAddr,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    let host_port = match target {
        TargetAddr::Ip(sa) => sa.to_string(),
        TargetAddr::Domain(host, port) => format!("{}:{}", host, port),
    };

    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
        host_port, host_port
    );

    if let Some((user, pass)) = auth {
        let auth_str = format!("{}:{}", user, pass);
        let encoded = base64_encode(auth_str.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // 读取响应状态行 (例如 "HTTP/1.1 200 Connection Established\r\n")
    let mut resp_buf = Vec::new();
    let mut byte = [0u8; 1];
    while resp_buf.len() < 4096 {
        stream.read_exact(&mut byte).await?;
        resp_buf.push(byte[0]);
        if resp_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&resp_buf);
    let status_line = resp_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() >= 2 {
        if let Ok(code) = parts[1].parse::<u16>() {
            if (200..300).contains(&code) {
                return Ok(());
            } else {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("HTTP CONNECT 代理拒绝连接: {}", status_line),
                )));
            }
        }
    }

    Err(ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("HTTP CONNECT 响应格式异常: {}", status_line),
    )))
}

/// 探测上游代理连通性及握手状态（支持 SOCKS5 与 HTTP CONNECT），返回握手耗时
pub async fn check_upstream_health_auto(
    upstream: SocketAddr,
    is_http: bool,
    auth: Option<(&str, &str)>,
    timeout_dur: std::time::Duration,
) -> Result<std::time::Duration> {
    let start = std::time::Instant::now();
    let mut stream = tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(upstream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "连接上游代理超时"))?
        .map_err(ProtocolError::Io)?;

    if is_http {
        let req = if let Some((user, pass)) = auth {
            let cred = format!("{}:{}", user, pass);
            let b64 = base64_encode(cred.as_bytes());
            format!(
                "CONNECT 127.0.0.1:0 HTTP/1.1\r\nHost: 127.0.0.1:0\r\nProxy-Authorization: Basic {}\r\nProxy-Connection: close\r\n\r\n",
                b64
            )
        } else {
            "CONNECT 127.0.0.1:0 HTTP/1.1\r\nHost: 127.0.0.1:0\r\nProxy-Connection: close\r\n\r\n".to_string()
        };
        tokio::time::timeout(timeout_dur, stream.write_all(req.as_bytes()))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "上游 HTTP 探活超时"))?
            .map_err(ProtocolError::Io)?;

        let mut buf = [0u8; 12];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "上游 HTTP 握手响应超时"))?
            .map_err(ProtocolError::Io)?;
        if !buf.starts_with(b"HTTP/1.") {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "上游非有效 HTTP 代理",
            )));
        }
    } else {
        tokio::time::timeout(timeout_dur, socks5_handshake(&mut stream, auth))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "上游 SOCKS5 握手超时"))??;
    }

    Ok(start.elapsed())
}

/// 探测上游代理连通性及 SOCKS5 认证握手状态，返回握手耗时（向前兼容接口）
pub async fn check_upstream_health(
    upstream: SocketAddr,
    auth: Option<(&str, &str)>,
    timeout_dur: std::time::Duration,
) -> Result<std::time::Duration> {
    check_upstream_health_auto(upstream, false, auth, timeout_dur).await
}
