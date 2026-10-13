//! shadow-core/dns: DNS-over-TCP (RFC 7766 / RFC 1035) 客户端实现
//!
//! 在严格防泄漏模式 (strict_dns=true) 下，为直连域名提供无明文 UDP/53 泄漏的安全解析通道。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS 解析超时")]
    Timeout,
    #[error("非法或过长域名: {0}")]
    InvalidDomain(String),
    #[error("DNS 服务端响应格式错误: {0}")]
    MalformedResponse(String),
    #[error("DNS 查询返回错误码 (RCODE: {0})")]
    ServerFailure(u8),
    #[error("未查询到有效 A 记录 (域名: {0})")]
    NoRecord(String),
}

/// 构造标准 DNS 查询包 (RFC 1035)
pub fn build_query_packet(domain: &str, tx_id: u16) -> Result<Vec<u8>, DnsError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(DnsError::InvalidDomain(domain.to_string()));
    }

    let mut buf = Vec::with_capacity(64);

    // 1. DNS 报头 (12 字节)
    buf.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
    buf.extend_from_slice(&[0x01, 0x00]);         // Flags: RD=1 (期望递归查询)
    buf.extend_from_slice(&[0x00, 0x01]);         // QDCOUNT: 1
    buf.extend_from_slice(&[0x00, 0x00]);         // ANCOUNT: 0
    buf.extend_from_slice(&[0x00, 0x00]);         // NSCOUNT: 0
    buf.extend_from_slice(&[0x00, 0x00]);         // ARCOUNT: 0

    // 2. Question: QNAME (以点分割的 label 列表)
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidDomain(domain.to_string()));
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(DnsError::InvalidDomain(format!("标签过长: {}", label)));
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0x00); // 终止根 label

    // QTYPE: 0x0001 (A 记录)
    buf.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: 0x0001 (IN 互联网)
    buf.extend_from_slice(&[0x00, 0x01]);

    Ok(buf)
}

/// 解析 DNS 响应包并提取首个 IPv4 A 记录 (RFC 1035)
pub fn parse_response_packet(domain: &str, expected_id: u16, buf: &[u8]) -> Result<Ipv4Addr, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::MalformedResponse("报文长度小于 12 字节".into()));
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(DnsError::MalformedResponse(format!(
            "事务 ID 不匹配 (预期: {}, 实际: {})",
            expected_id, id
        )));
    }

    let qr = (buf[2] >> 7) & 1;
    if qr != 1 {
        return Err(DnsError::MalformedResponse("非响应报文 (QR!=1)".into()));
    }

    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return Err(DnsError::ServerFailure(rcode));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return Err(DnsError::NoRecord(domain.to_string()));
    }

    let mut offset = 12;

    // 跳过 Question 区域
    for _ in 0..qdcount {
        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + len;
        }
        // QTYPE (2) + QCLASS (2)
        offset += 4;
    }

    if offset > buf.len() {
        return Err(DnsError::MalformedResponse("Question 区域解析越界".into()));
    }

    // 解析 Answer 区域
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        // 跳过 Name 字段 (指针或 label 序列)
        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + len;
        }

        if offset + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        // 命中 A 记录 (TYPE = 1) 且长度为 4 字节
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            return Ok(ip);
        }

        offset += rdlength;
    }

    Err(DnsError::NoRecord(domain.to_string()))
}

/// 通过 DNS-over-TCP 向安全 DNS 递归服务器查询域名的 A 记录 (RFC 7766)
pub async fn resolve_dns_over_tcp(
    dns_server: SocketAddr,
    domain: &str,
    timeout_dur: Duration,
) -> Result<IpAddr, DnsError> {
    let tx_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() & 0xFFFF) as u16;

    let query_payload = build_query_packet(domain, tx_id)?;
    let msg_len = query_payload.len() as u16;

    let mut stream = timeout(timeout_dur, TcpStream::connect(dns_server))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(DnsError::Io)?;

    // RFC 7766: TCP DNS 报文前置 2 字节大端序长度
    let mut tcp_buf = Vec::with_capacity(2 + query_payload.len());
    tcp_buf.extend_from_slice(&msg_len.to_be_bytes());
    tcp_buf.extend_from_slice(&query_payload);

    timeout(timeout_dur, stream.write_all(&tcp_buf))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(DnsError::Io)?;

    // 读取响应长度
    let mut len_buf = [0u8; 2];
    timeout(timeout_dur, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(DnsError::Io)?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if !(12..=4096).contains(&resp_len) {
        return Err(DnsError::MalformedResponse(format!(
            "无效的 TCP DNS 响应长度: {}",
            resp_len
        )));
    }

    let mut resp_buf = vec![0u8; resp_len];
    timeout(timeout_dur, stream.read_exact(&mut resp_buf))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(DnsError::Io)?;

    let ip = parse_response_packet(domain, tx_id, &resp_buf)?;
    Ok(IpAddr::V4(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_dns_packet() {
        let domain = "example.com";
        let tx_id = 0xABCD;
        let query = build_query_packet(domain, tx_id).unwrap();
        assert_eq!(&query[0..2], &[0xAB, 0xCD]);
        assert_eq!(&query[2..4], &[0x01, 0x00]);

        // 模拟构造标准响应包 (Answer 含 93.184.216.34)
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0xAB, 0xCD]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RA=1
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT: 1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question: 7example3com0 + Type(1) + Class(1)
        resp.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer: 指针压缩指向 12 偏移 (0xC00C) + Type A (1) + Class IN (1) + TTL (300) + RdLength (4) + IP (93.184.216.34)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[93, 184, 216, 34]);

        let parsed_ip = parse_response_packet(domain, tx_id, &resp).unwrap();
        assert_eq!(parsed_ip, Ipv4Addr::new(93, 184, 216, 34));
    }

    #[test]
    fn test_invalid_domain_rejected() {
        assert!(build_query_packet("", 1).is_err());
        assert!(build_query_packet("bad..domain", 1).is_err());
    }
}
