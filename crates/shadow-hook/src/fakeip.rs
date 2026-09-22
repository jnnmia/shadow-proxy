//! ghost-hook/fakeip: RFC 2544 Fake-IP 保留网段 (198.18.0.0/15) 内存映射与严格防泄漏

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;

/// Fake-IP 起始与终止范围 (198.18.0.1 ~ 198.19.255.254)
pub const FAKE_IP_START: u32 = 0xC6120001; // 198.18.0.1
pub const FAKE_IP_END: u32 = 0xC613FFFE;   // 198.19.255.254

static NEXT_FAKE_IP: AtomicU32 = AtomicU32::new(FAKE_IP_START);

/// 进程内存中的双向映射表
struct FakeIpTable {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
}

impl FakeIpTable {
    fn new() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
        }
    }
}

static TABLE: RwLock<Option<FakeIpTable>> = RwLock::new(None);

fn with_table_read<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&FakeIpTable) -> R,
{
    let guard = TABLE.read().ok()?;
    guard.as_ref().map(f)
}

fn with_table_write<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut FakeIpTable) -> R,
{
    let mut guard = TABLE.write().ok()?;
    if guard.is_none() {
        *guard = Some(FakeIpTable::new());
    }
    guard.as_mut().map(f)
}

/// 判断给定的 IPv4 地址是否落在 Fake-IP 保留网段内 (198.18.0.0/15)
pub fn is_fake_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

pub const MAX_FAKE_IP_ENTRIES: usize = 65536;

/// 获取或分配域名对应的 Fake-IP
pub fn get_or_allocate_fake_ip(domain: &str) -> Ipv4Addr {
    let domain_lower = domain.to_ascii_lowercase();

    // 1. 先进行只读查询，命中缓存则立即返回
    if let Some(Some(ip)) = with_table_read(|tbl| tbl.domain_to_ip.get(&domain_lower).copied()) {
        return ip;
    }

    // 2. 未命中，进入写锁分配新 Fake-IP
    with_table_write(|tbl| {
        if let Some(&ip) = tbl.domain_to_ip.get(&domain_lower) {
            return ip;
        }

        // 容量防护：防止高频随机域名探测导致内存耗尽 (DoS)
        if tbl.domain_to_ip.len() >= MAX_FAKE_IP_ENTRIES {
            if let Some((old_ip, old_domain)) = tbl.ip_to_domain.iter().next().map(|(k, v)| (*k, v.clone())) {
                tbl.ip_to_domain.remove(&old_ip);
                tbl.domain_to_ip.remove(&old_domain);
            }
        }

        let curr = NEXT_FAKE_IP.fetch_add(1, Ordering::Relaxed);
        let val = if curr > FAKE_IP_END {
            NEXT_FAKE_IP.store(FAKE_IP_START + 1, Ordering::Relaxed);
            FAKE_IP_START
        } else {
            curr
        };

        let new_ip = Ipv4Addr::from(val.to_be_bytes());

        // 状态机原子性：若该 IP 此前已分配给其它域名（如回卷），清除旧映射，杜绝反向串线劫持
        if let Some(old_domain) = tbl.ip_to_domain.remove(&new_ip) {
            tbl.domain_to_ip.remove(&old_domain);
        }

        tbl.domain_to_ip.insert(domain_lower.clone(), new_ip);
        tbl.ip_to_domain.insert(new_ip, domain_lower);
        new_ip
    })
    .unwrap_or(Ipv4Addr::new(198, 18, 0, 1))
}

/// 根据 Fake-IP 反查原始域名
pub fn lookup_domain_by_ip(ip: &Ipv4Addr) -> Option<String> {
    if !is_fake_ip(ip) {
        return None;
    }
    with_table_read(|tbl| tbl.ip_to_domain.get(ip).cloned()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_fake_ip() {
        assert!(is_fake_ip(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_fake_ip(&Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_fake_ip(&Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_fake_ip(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_fake_ip(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_allocate_and_lookup() {
        let domain = "test.proxy.example.com";
        let ip = get_or_allocate_fake_ip(domain);
        assert!(is_fake_ip(&ip));

        // 再次获取应返回相同 Fake-IP
        let ip_repeat = get_or_allocate_fake_ip(domain);
        assert_eq!(ip, ip_repeat);

        // 反查域名应匹配原始域名 (忽略大小写)
        let resolved = lookup_domain_by_ip(&ip);
        assert_eq!(resolved.as_deref(), Some(domain));

        let non_fake = Ipv4Addr::new(8, 8, 8, 8);
        assert_eq!(lookup_domain_by_ip(&non_fake), None);
    }

    #[test]
    fn test_fakeip_collision_cleanup() {
        with_table_write(|tbl| {
            let fake_ip = Ipv4Addr::new(198, 18, 1, 1);
            tbl.domain_to_ip.insert("domain-a.com".into(), fake_ip);
            tbl.ip_to_domain.insert(fake_ip, "domain-a.com".into());

            // 模拟分配相同 IP 给新域名
            if let Some(old) = tbl.ip_to_domain.remove(&fake_ip) {
                tbl.domain_to_ip.remove(&old);
            }
            tbl.domain_to_ip.insert("domain-b.com".into(), fake_ip);
            tbl.ip_to_domain.insert(fake_ip, "domain-b.com".into());

            // domain-a 应当已被剔除，杜绝串线
            assert_eq!(tbl.domain_to_ip.get("domain-a.com"), None);
            assert_eq!(tbl.ip_to_domain.get(&fake_ip).map(|s| s.as_str()), Some("domain-b.com"));
        });
    }
}
