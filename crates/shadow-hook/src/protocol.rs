//! ghost-hook/protocol: 微运行时同步二进制帧头编码器 (与 ghost-core 严格对称)

use std::net::SocketAddr;

pub const GHOST_MAGIC: [u8; 4] = *b"GHST";
pub const MAX_DOMAIN_LEN: usize = 255;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HookTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl HookTarget {
    /// 编码为本地中继帧格式：
    /// [4 字节 MAGIC: "GHST"]
    /// [1 字节 类型: 0x01=IPv4, 0x03=Domain, 0x04=IPv6]
    /// [地址数据...]
    /// [2 字节 端口 (Big Endian)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&GHOST_MAGIC);
        match self {
            HookTarget::Ip(SocketAddr::V4(v4)) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            HookTarget::Ip(SocketAddr::V6(v6)) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            HookTarget::Domain(host, port) => {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_encode_ipv4() {
        let target = HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            8080,
        )));
        let encoded = target.encode();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x01);
        assert_eq!(&encoded[5..9], &[1, 2, 3, 4]);
        assert_eq!(&encoded[9..11], &8080u16.to_be_bytes());
    }

    #[test]
    fn test_encode_domain() {
        let target = HookTarget::Domain("api.github.com".to_string(), 443);
        let encoded = target.encode();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x03);
        assert_eq!(encoded[5], "api.github.com".len() as u8);
        assert_eq!(&encoded[6..6 + 14], b"api.github.com");
        assert_eq!(&encoded[20..22], &443u16.to_be_bytes());
    }

    #[test]
    fn test_encode_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let target = HookTarget::Ip(SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 0)));
        let encoded = target.encode();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x04);
        assert_eq!(&encoded[5..21], &ip.octets());
        assert_eq!(&encoded[21..23], &80u16.to_be_bytes());
    }
}
