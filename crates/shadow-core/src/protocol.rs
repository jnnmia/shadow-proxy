//! ghost-core/protocol: 本地中继帧头与上游 SOCKS5 协议实现

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const GHOST_MAGIC: [u8; 4] = *b"GHST";
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

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    /// 编码为本地中继帧格式：
    /// [4 字节 MAGIC: "GHST"]
    /// [1 字节 类型: 0x01=IPv4, 0x03=Domain, 0x04=IPv6]
    /// [地址数据...]
    /// [2 字节 端口 (Big Endian)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&GHOST_MAGIC);
        match self {
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
        buf
    }

    /// 从异步流中解码本地中继帧头
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        if magic != GHOST_MAGIC {
            return Err(ProtocolError::InvalidMagic(magic));
        }

        let addr_type = reader.read_u8().await?;
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
}

/// 执行 SOCKS5 握手并连接至目标地址 (RFC 1928)
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &TargetAddr,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    // 1. 发送认证协商
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
            } else {
                return Err(ProtocolError::Socks5("服务端要求认证但未提供凭据".into()));
            }
        }
        0xff => {
            return Err(ProtocolError::Socks5("服务端拒绝了所有可用的认证方式".into()));
        }
        other => {
            return Err(ProtocolError::Socks5(format!("不支持的认证类型: 0x{:02x}", other)));
        }
    }

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
