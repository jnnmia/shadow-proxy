//! ghost-hook/fakeip: RFC 2544 Fake-IP 保留网段 (198.18.0.0/15) 内存映射与严格防泄漏

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;

/// Fake-IP 起始与终止范围 (198.18.0.1 ~ 198.19.255.254)
pub const FAKE_IP_START: u32 = 0xC6120001; // 198.18.0.1
pub const FAKE_IP_END: u32 = 0xC613FFFE;   // 198.19.255.254

static NEXT_FAKE_IP: AtomicU32 = AtomicU32::new(FAKE_IP_START);

/// 进程内存中的双向映射与 LRU 状态表
pub struct FakeIpTable {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, (String, u64)>,
    access_order: BTreeMap<u64, Ipv4Addr>,
    current_tick: u64,
}

impl Default for FakeIpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIpTable {
    pub fn new() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            access_order: BTreeMap::new(),
            current_tick: 0,
        }
    }

    /// 更新条目的 LRU 访问序号 (置于最新)
    fn touch(&mut self, ip: Ipv4Addr) {
        if let Some((_, tick)) = self.ip_to_domain.get_mut(&ip) {
            self.access_order.remove(tick);
            self.current_tick += 1;
            *tick = self.current_tick;
            self.access_order.insert(self.current_tick, ip);
        }
    }

    /// 淘汰最久未访问的条目
    fn evict_oldest(&mut self) -> Option<(Ipv4Addr, String)> {
        let (&oldest_tick, &oldest_ip) = self.access_order.iter().next()?;
        self.access_order.remove(&oldest_tick);
        if let Some((old_domain, _)) = self.ip_to_domain.remove(&oldest_ip) {
            self.domain_to_ip.remove(&old_domain);
            Some((oldest_ip, old_domain))
        } else {
            None
        }
    }

    /// 按照指定最大容量分配或查询 Fake-IP
    pub fn get_or_allocate_with_capacity(
        &mut self,
        domain_lower: &str,
        max_entries: usize,
        next_ip_provider: impl FnOnce() -> Ipv4Addr,
    ) -> Ipv4Addr {
        if let Some(&ip) = self.domain_to_ip.get(domain_lower) {
            self.touch(ip);
            return ip;
        }

        // 容量防护：淘汰最久未使用的条目 (LRU 算法)，杜绝随机踢出导致活跃连接反向串线
        while self.domain_to_ip.len() >= max_entries {
            if self.evict_oldest().is_none() {
                break;
            }
        }

        let new_ip = next_ip_provider();

        // 状态机原子性：若该 IP 此前已分配给其它域名（如回卷），清除旧映射
        if let Some((old_domain, old_tick)) = self.ip_to_domain.remove(&new_ip) {
            self.access_order.remove(&old_tick);
            self.domain_to_ip.remove(&old_domain);
        }

        self.current_tick += 1;
        self.access_order.insert(self.current_tick, new_ip);
        self.ip_to_domain.insert(new_ip, (domain_lower.to_string(), self.current_tick));
        self.domain_to_ip.insert(domain_lower.to_string(), new_ip);

        new_ip
    }

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<&str> {
        self.ip_to_domain.get(ip).map(|(d, _)| d.as_str())
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
        // 如果命中，尝试异步更新 LRU 访问热度（写锁不争抢）
        if let Ok(mut guard) = TABLE.try_write() {
            if let Some(tbl) = guard.as_mut() {
                tbl.touch(ip);
            }
        }
        return ip;
    }

    // 2. 未命中，进入写锁分配新 Fake-IP
    with_table_write(|tbl| {
        tbl.get_or_allocate_with_capacity(&domain_lower, MAX_FAKE_IP_ENTRIES, || {
            let curr = NEXT_FAKE_IP.fetch_add(1, Ordering::Relaxed);
            let val = if curr > FAKE_IP_END {
                NEXT_FAKE_IP.store(FAKE_IP_START + 1, Ordering::Relaxed);
                FAKE_IP_START
            } else {
                curr
            };
            Ipv4Addr::from(val.to_be_bytes())
        })
    })
    .unwrap_or(Ipv4Addr::new(198, 18, 0, 1))
}

/// 根据 Fake-IP 反查原始域名
pub fn lookup_domain_by_ip(ip: &Ipv4Addr) -> Option<String> {
    if !is_fake_ip(ip) {
        return None;
    }
    with_table_read(|tbl| tbl.lookup(ip).map(|s| s.to_string())).flatten()
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
    fn test_fakeip_lru_eviction() {
        let mut tbl = FakeIpTable::new();
        let ip1 = Ipv4Addr::new(198, 18, 0, 1);
        let ip2 = Ipv4Addr::new(198, 18, 0, 2);
        let ip3 = Ipv4Addr::new(198, 18, 0, 3);

        // 容量限制为 2
        let cap = 2;
        let mut counter = 1u8;
        let mut alloc = |domain: &str| {
            tbl.get_or_allocate_with_capacity(domain, cap, || {
                let ip = Ipv4Addr::new(198, 18, 0, counter);
                counter += 1;
                ip
            })
        };

        let allocated1 = alloc("a.com");
        assert_eq!(allocated1, ip1);
        let allocated2 = alloc("b.com");
        assert_eq!(allocated2, ip2);

        // 重新访问 a.com，使其变为最近使用 (Most Recently Used)
        let allocated1_again = alloc("a.com");
        assert_eq!(allocated1_again, ip1);

        // 插入第 3 个域名 c.com，容量达到限制，应淘汰最久未访问的 b.com 而非活跃的 a.com
        let allocated3 = alloc("c.com");
        assert_eq!(allocated3, ip3);

        // 验证 b.com 已被淘汰，a.com 与 c.com 依然存活
        assert_eq!(tbl.domain_to_ip.get("b.com"), None);
        assert_eq!(tbl.lookup(&ip2), None);
        assert_eq!(tbl.lookup(&ip1), Some("a.com"));
        assert_eq!(tbl.lookup(&ip3), Some("c.com"));
    }

    #[test]
    fn test_fakeip_collision_cleanup() {
        let mut tbl = FakeIpTable::new();
        let fake_ip = Ipv4Addr::new(198, 18, 1, 1);

        // 初始分配给 domain-a.com
        let ip_a = tbl.get_or_allocate_with_capacity("domain-a.com", 10, || fake_ip);
        assert_eq!(ip_a, fake_ip);
        assert_eq!(tbl.lookup(&fake_ip), Some("domain-a.com"));

        // 当 IP 回卷发生碰撞，重新分配给 domain-b.com
        let ip_b = tbl.get_or_allocate_with_capacity("domain-b.com", 10, || fake_ip);
        assert_eq!(ip_b, fake_ip);

        // domain-a 必须被彻底清除，反查必须是 domain-b，杜绝串线
        assert_eq!(tbl.domain_to_ip.get("domain-a.com"), None);
        assert_eq!(tbl.lookup(&fake_ip), Some("domain-b.com"));
    }
}
