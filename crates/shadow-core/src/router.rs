//! shadow-core/router: 多条件分流路由规则引擎
//!
//! 支持域名后缀、关键词、全等、IP-CIDR、端口及范围匹配。
//! 提供 Direct（直连）、Proxy（走代理）、Block（阻断）三种决策动作。

use crate::protocol::TargetAddr;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// 路由分流决策动作
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    /// 直连目标（不经由上游代理）
    Direct,
    /// 转发至上游代理隧道
    Proxy,
    /// 丢弃或阻断连接
    Block,
}

impl std::fmt::Display for RouteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteAction::Direct => write!(f, "DIRECT"),
            RouteAction::Proxy => write!(f, "PROXY"),
            RouteAction::Block => write!(f, "BLOCK"),
        }
    }
}

/// 单条规则匹配模式
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RulePattern {
    /// 域名后缀匹配 (如 "cn", "baidu.com", 匹配 abc.cn, sub.baidu.com)
    DomainSuffix(String),
    /// 域名关键字匹配 (如 "google", 包含即命中)
    DomainKeyword(String),
    /// 域名精确匹配 (如 "raw.githubusercontent.com")
    DomainExact(String),
    /// IPv4 CIDR 范围 (如 "192.168.0.0/16", "10.0.0.0/8")
    IpCidr { ip: String, prefix_len: u8 },
    /// 单个目标端口 (如 80, 443)
    Port(u16),
    /// 目标端口范围 (如 8000..=9000)
    PortRange { start: u16, end: u16 },
    /// 默认兜底规则
    Final,
}

/// 分流规则条目
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RuleItem {
    pub id: String,
    pub name: String,
    pub pattern: RulePattern,
    pub action: RouteAction,
    pub enabled: bool,
}

/// 路由匹配结果
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub rule_name: String,
    pub pattern_desc: String,
}

/// 路由引擎管理器
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Router {
    pub rules: Vec<RuleItem>,
}

impl Default for Router {
    fn default() -> Self {
        Self::preset_smart()
    }
}

impl Router {
    pub fn new(rules: Vec<RuleItem>) -> Self {
        Self { rules }
    }

    /// 预设：智能分流（私有局域网直连、.cn 域名直连，其余走代理）
    pub fn preset_smart() -> Self {
        Self {
            rules: vec![
                RuleItem {
                    id: "smart-1".into(),
                    name: "环回地址直连".into(),
                    pattern: RulePattern::IpCidr {
                        ip: "127.0.0.0".into(),
                        prefix_len: 8,
                    },
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "smart-2".into(),
                    name: "内网 Class A 直连".into(),
                    pattern: RulePattern::IpCidr {
                        ip: "10.0.0.0".into(),
                        prefix_len: 8,
                    },
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "smart-3".into(),
                    name: "内网 Class B 直连".into(),
                    pattern: RulePattern::IpCidr {
                        ip: "172.16.0.0".into(),
                        prefix_len: 12,
                    },
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "smart-4".into(),
                    name: "内网 Class C 直连".into(),
                    pattern: RulePattern::IpCidr {
                        ip: "192.168.0.0".into(),
                        prefix_len: 16,
                    },
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "smart-5".into(),
                    name: "中国大陆顶级域名直连".into(),
                    pattern: RulePattern::DomainSuffix("cn".into()),
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "smart-final".into(),
                    name: "默认代理".into(),
                    pattern: RulePattern::Final,
                    action: RouteAction::Proxy,
                    enabled: true,
                },
            ],
        }
    }

    /// 预设：全局代理（除环回地址外全部走上游代理）
    pub fn preset_global_proxy() -> Self {
        Self {
            rules: vec![
                RuleItem {
                    id: "global-1".into(),
                    name: "环回地址直连".into(),
                    pattern: RulePattern::IpCidr {
                        ip: "127.0.0.0".into(),
                        prefix_len: 8,
                    },
                    action: RouteAction::Direct,
                    enabled: true,
                },
                RuleItem {
                    id: "global-final".into(),
                    name: "全部走代理".into(),
                    pattern: RulePattern::Final,
                    action: RouteAction::Proxy,
                    enabled: true,
                },
            ],
        }
    }

    /// 预设：全部直连（调试或恢复网络）
    pub fn preset_direct_all() -> Self {
        Self {
            rules: vec![RuleItem {
                id: "direct-final".into(),
                name: "全部直连".into(),
                pattern: RulePattern::Final,
                action: RouteAction::Direct,
                enabled: true,
            }],
        }
    }

    /// 评估目标地址并返回路由匹配决策
    pub fn eval(&self, target: &TargetAddr) -> RouteDecision {
        let (host, port, ip_opt) = match target {
            TargetAddr::Ip(sa) => {
                let ip = sa.ip();
                let port = sa.port();
                let ip_v4 = match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                };
                (ip.to_string(), port, ip_v4)
            }
            TargetAddr::Domain(domain, port) => {
                let ip_v4 = domain.parse::<Ipv4Addr>().ok();
                (domain.clone(), *port, ip_v4)
            }
        };

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if Self::match_pattern(&rule.pattern, &host, port, ip_opt) {
                return RouteDecision {
                    action: rule.action,
                    rule_name: rule.name.clone(),
                    pattern_desc: Self::format_pattern(&rule.pattern),
                };
            }
        }

        // 默认兜底动作
        RouteDecision {
            action: RouteAction::Proxy,
            rule_name: "默认保底代理".into(),
            pattern_desc: "DEFAULT_FALLBACK".into(),
        }
    }

    fn match_pattern(
        pattern: &RulePattern,
        host: &str,
        port: u16,
        ip_v4: Option<Ipv4Addr>,
    ) -> bool {
        match pattern {
            RulePattern::DomainSuffix(suffix) => {
                let s = suffix.trim_start_matches('.').to_ascii_lowercase();
                let h = host.to_ascii_lowercase();
                h == s || h.ends_with(&format!(".{}", s))
            }
            RulePattern::DomainKeyword(kw) => {
                let k = kw.to_ascii_lowercase();
                host.to_ascii_lowercase().contains(&k)
            }
            RulePattern::DomainExact(exact) => {
                host.eq_ignore_ascii_case(exact)
            }
            RulePattern::IpCidr { ip, prefix_len } => {
                if let Some(target_v4) = ip_v4 {
                    if let Ok(net_v4) = ip.parse::<Ipv4Addr>() {
                        return Self::cidr_matches_v4(target_v4, net_v4, *prefix_len);
                    }
                }
                false
            }
            RulePattern::Port(p) => port == *p,
            RulePattern::PortRange { start, end } => port >= *start && port <= *end,
            RulePattern::Final => true,
        }
    }

    fn cidr_matches_v4(ip: Ipv4Addr, net: Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len == 0 {
            return true;
        }
        if prefix_len > 32 {
            return false;
        }
        let mask = if prefix_len == 32 {
            u32::MAX
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        (u32::from(ip) & mask) == (u32::from(net) & mask)
    }

    fn format_pattern(pattern: &RulePattern) -> String {
        match pattern {
            RulePattern::DomainSuffix(s) => format!("*.{}", s),
            RulePattern::DomainKeyword(k) => format!("Keyword({})", k),
            RulePattern::DomainExact(e) => format!("Exact({})", e),
            RulePattern::IpCidr { ip, prefix_len } => format!("{}/{}", ip, prefix_len),
            RulePattern::Port(p) => format!("Port({})", p),
            RulePattern::PortRange { start, end } => format!("Port({}-{})", start, end),
            RulePattern::Final => "FINAL".into(),
        }
    }

    pub fn add_rule(&mut self, rule: RuleItem) {
        // 插入在 Final 规则之前
        if let Some(pos) = self.rules.iter().position(|r| matches!(r.pattern, RulePattern::Final)) {
            self.rules.insert(pos, rule);
        } else {
            self.rules.push(rule);
        }
    }

    pub fn remove_rule(&mut self, id: &str) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn set_rule_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.enabled = enabled;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_domain_matching() {
        let router = Router::preset_smart();

        // .cn 后缀应匹配直连
        let target_cn = TargetAddr::Domain("news.sina.com.cn".into(), 443);
        let dec = router.eval(&target_cn);
        assert_eq!(dec.action, RouteAction::Direct);

        // .com 域名应走代理 (命中了默认代理)
        let target_google = TargetAddr::Domain("www.google.com".into(), 443);
        let dec = router.eval(&target_google);
        assert_eq!(dec.action, RouteAction::Proxy);
    }

    #[test]
    fn test_cidr_matching() {
        let router = Router::preset_smart();

        // 127.0.0.1 环回直连
        let addr_local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dec = router.eval(&TargetAddr::Ip(addr_local));
        assert_eq!(dec.action, RouteAction::Direct);

        // 192.168.1.50 内网直连
        let addr_lan: SocketAddr = "192.168.1.50:22".parse().unwrap();
        let dec = router.eval(&TargetAddr::Ip(addr_lan));
        assert_eq!(dec.action, RouteAction::Direct);

        // 8.8.8.8 公网 IP 走代理
        let addr_wan: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dec = router.eval(&TargetAddr::Ip(addr_wan));
        assert_eq!(dec.action, RouteAction::Proxy);
    }

    #[test]
    fn test_port_and_block_rules() {
        let mut router = Router::preset_smart();

        // 添加一条阻断 25 端口 (SMTP) 规则
        router.add_rule(RuleItem {
            id: "block-smtp".into(),
            name: "阻断 SMTP".into(),
            pattern: RulePattern::Port(25),
            action: RouteAction::Block,
            enabled: true,
        });

        let target_smtp = TargetAddr::Domain("mail.example.com".into(), 25);
        let dec = router.eval(&target_smtp);
        assert_eq!(dec.action, RouteAction::Block);

        // 测试禁用规则
        router.set_rule_enabled("block-smtp", false);
        let dec2 = router.eval(&target_smtp);
        assert_eq!(dec2.action, RouteAction::Proxy);
    }
}
