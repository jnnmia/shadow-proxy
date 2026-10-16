//! shadow-hook/protocol: 微运行时同步二进制帧头编码器 (与 shadow-core 严格对称)

use std::net::SocketAddr;
use std::sync::OnceLock;

pub const GHOST_MAGIC: [u8; 4] = *b"GHST";
pub const SHADOW_MAGIC: [u8; 4] = *b"SHAD";
pub const MAX_DOMAIN_LEN: usize = 255;

static PROCESS_INFO: OnceLock<(u32, String)> = OnceLock::new();

pub fn get_process_info() -> (u32, &'static str) {
    let (pid, name) = PROCESS_INFO.get_or_init(|| {
        let pid = std::process::id();
        let name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown.exe".to_string());
        (pid, name)
    });
    (*pid, name.as_str())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HookTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl HookTarget {
    /// 默认编码为本地中继帧 v2 格式（携带 PID 与进程名，由 shadow-core 自动识别并分流）
    pub fn encode(&self) -> Vec<u8> {
        self.encode_v2()
    }

    /// 编码为本地中继帧 v2 格式：
    /// [4 字节 MAGIC: "SHAD"]
    /// [1 字节 版本号: 0x02]
    /// [4 字节 PID (Big Endian)]
    /// [1 字节 进程名长度 N (0..=64)]
    /// [N 字节 进程名 UTF-8]
    /// [1 字节 类型: 0x01=IPv4, 0x03=Domain, 0x04=IPv6]
    /// [地址数据...]
    /// [2 字节 端口 (Big Endian)]
    pub fn encode_v2(&self) -> Vec<u8> {
        let (pid, proc_name) = get_process_info();
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&SHADOW_MAGIC);
        buf.push(0x02);
        buf.extend_from_slice(&pid.to_be_bytes());

        let name_bytes = proc_name.as_bytes();
        let name_len = name_bytes.len().min(64) as u8;
        buf.push(name_len);
        if name_len > 0 {
            buf.extend_from_slice(&name_bytes[..name_len as usize]);
        }

        self.append_target_payload(&mut buf);
        buf
    }

    /// 编码为本地中继帧 v1 格式（向前兼容）
    pub fn encode_v1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&GHOST_MAGIC);
        self.append_target_payload(&mut buf);
        buf
    }

    fn append_target_payload(&self, buf: &mut Vec<u8>) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_encode_v2_structure() {
        let target = HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            8080,
        )));
        let encoded = target.encode(); // encode() 默认调用 encode_v2()
        assert_eq!(&encoded[0..4], b"SHAD");
        assert_eq!(encoded[4], 0x02);
        let (pid, proc_name) = get_process_info();
        assert_eq!(&encoded[5..9], &pid.to_be_bytes());
        let name_len = encoded[9] as usize;
        assert_eq!(&encoded[10..10 + name_len], proc_name.as_bytes());
        let target_start = 10 + name_len;
        assert_eq!(encoded[target_start], 0x01);
        assert_eq!(&encoded[target_start + 1..target_start + 5], &[1, 2, 3, 4]);
        assert_eq!(&encoded[target_start + 5..target_start + 7], &8080u16.to_be_bytes());
    }

    #[test]
    fn test_encode_v1_ipv4() {
        let target = HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            8080,
        )));
        let encoded = target.encode_v1();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x01);
        assert_eq!(&encoded[5..9], &[1, 2, 3, 4]);
        assert_eq!(&encoded[9..11], &8080u16.to_be_bytes());
    }

    #[test]
    fn test_encode_v1_domain() {
        let target = HookTarget::Domain("api.github.com".to_string(), 443);
        let encoded = target.encode_v1();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x03);
        assert_eq!(encoded[5], "api.github.com".len() as u8);
        assert_eq!(&encoded[6..6 + 14], b"api.github.com");
        assert_eq!(&encoded[20..22], &443u16.to_be_bytes());
    }

    #[test]
    fn test_encode_v1_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let target = HookTarget::Ip(SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 0)));
        let encoded = target.encode_v1();
        assert_eq!(&encoded[0..4], b"GHST");
        assert_eq!(encoded[4], 0x04);
        assert_eq!(&encoded[5..21], &ip.octets());
        assert_eq!(&encoded[21..23], &80u16.to_be_bytes());
    }
}
