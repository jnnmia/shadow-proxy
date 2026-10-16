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
    /// 发起进程名匹配 (如 "git.exe", "curl.exe")
    ProcessName(String),
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

    /// 评估目标地址并返回路由匹配决策（保持向前兼容）
    pub fn eval(&self, target: &TargetAddr) -> RouteDecision {
        self.eval_with_proc(target, None)
    }

    /// 评估目标地址与发起进程名，并返回路由匹配决策
    pub fn eval_with_proc(&self, target: &TargetAddr, proc_name: Option<&str>) -> RouteDecision {
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

            if Self::match_pattern(&rule.pattern, &host, port, ip_opt, proc_name) {
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
        proc_name: Option<&str>,
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
            RulePattern::ProcessName(expected) => {
                if let Some(actual) = proc_name {
                    let act = actual.to_ascii_lowercase();
                    let exp = expected.to_ascii_lowercase();
                    if act == exp {
                        return true;
                    }
                    if !exp.ends_with(".exe") && format!("{}.exe", exp) == act {
                        return true;
                    }
                }
                false
            }
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
            RulePattern::ProcessName(p) => format!("Process({})", p),
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

    /// 重新调整规则优先级位置
    pub fn move_rule(&mut self, from: usize, to: usize) -> bool {
        if from >= self.rules.len() || to >= self.rules.len() || from == to {
            return false;
        }
        let rule = self.rules.remove(from);
        self.rules.insert(to, rule);
        true
    }

    /// 清空所有自定义规则（仅保留 Final 兜底规则）
    pub fn clear_custom_rules(&mut self) {
        self.rules.retain(|r| matches!(r.pattern, RulePattern::Final));
    }

    /// 序列化为规范 JSON 字符串
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// 从 JSON 字符串解析 Router 配置
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
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

    #[test]
    fn test_process_name_routing() {
        let mut router = Router::preset_direct_all();

        // 添加规则：git.exe 走代理，curl 走直连，bad.exe 阻断
        router.add_rule(RuleItem {
            id: "proc-git".into(),
            name: "Git 强制代理".into(),
            pattern: RulePattern::ProcessName("git.exe".into()),
            action: RouteAction::Proxy,
            enabled: true,
        });
        router.add_rule(RuleItem {
            id: "proc-bad".into(),
            name: "恶意程序阻断".into(),
            pattern: RulePattern::ProcessName("malicious".into()), // 自动补充 .exe 匹配
            action: RouteAction::Block,
            enabled: true,
        });

        let target = TargetAddr::Domain("github.com".into(), 443);

        // 1. git.exe 发起 -> PROXY
        let dec_git = router.eval_with_proc(&target, Some("git.exe"));
        assert_eq!(dec_git.action, RouteAction::Proxy);
        assert_eq!(dec_git.rule_name, "Git 强制代理");

        // 2. GIT.EXE 大写发起 -> PROXY
        let dec_git_upper = router.eval_with_proc(&target, Some("GIT.EXE"));
        assert_eq!(dec_git_upper.action, RouteAction::Proxy);

        // 3. malicious.exe 发起 -> BLOCK (无 .exe 后缀规则智能匹配)
        let dec_bad = router.eval_with_proc(&target, Some("malicious.exe"));
        assert_eq!(dec_bad.action, RouteAction::Block);

        // 4. curl.exe 发起 -> DIRECT (命中 final 规则)
        let dec_curl = router.eval_with_proc(&target, Some("curl.exe"));
        assert_eq!(dec_curl.action, RouteAction::Direct);

        // 5. 无进程名发起 -> DIRECT
        let dec_none = router.eval_with_proc(&target, None);
        assert_eq!(dec_none.action, RouteAction::Direct);
    }

    #[test]
    fn test_router_reorder_and_json() {
        let mut router = Router::preset_direct_all();
        router.add_rule(RuleItem {
            id: "r1".into(),
            name: "Rule 1".into(),
            pattern: RulePattern::Port(80),
            action: RouteAction::Proxy,
            enabled: true,
        });
        router.add_rule(RuleItem {
            id: "r2".into(),
            name: "Rule 2".into(),
            pattern: RulePattern::Port(443),
            action: RouteAction::Block,
            enabled: true,
        });

        assert_eq!(router.rules[0].id, "r1");
        assert_eq!(router.rules[1].id, "r2");

        // 移动 r2 到第一位
        let ok = router.move_rule(1, 0);
        assert!(ok);
        assert_eq!(router.rules[0].id, "r2");
        assert_eq!(router.rules[1].id, "r1");

        // JSON 导出与恢复
        let json = router.to_json_pretty().unwrap();
        let loaded = Router::from_json(&json).unwrap();
        assert_eq!(loaded.rules.len(), router.rules.len());
        assert_eq!(loaded.rules[0].name, "Rule 2");
    }
}
