//! shadow-cli: 命令行启动器与中继转发管理引擎

use clap::Parser;
use shadow_core::relay::{RelayConfig, RelayServer};
use shadow_injector::{detect_architecture, spawn_and_inject_with_args, Architecture};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;

#[derive(Parser, Debug)]
#[command(
    name = "shadow-cli",
    author,
    version,
    about = "ShadowProxy CLI - 进程级透明代理启动器"
)]
struct Args {
    /// 目标程序可执行文件路径
    #[arg(short, long)]
    target: Option<PathBuf>,

    /// 目标程序启动参数 (例如: "--arg1 val1 -v")
    #[arg(short, long, allow_hyphen_values = true)]
    args: Option<String>,

    /// 上游 SOCKS5 代理服务器地址 (例如: 127.0.0.1:10808)
    #[arg(short, long, default_value = "127.0.0.1:10808")]
    proxy: String,

    /// 本地透明代理中继监听地址 (默认 127.0.0.1:0 动态分配空闲端口)
    #[arg(short, long, default_value = "127.0.0.1:0")]
    listen: String,

    /// 64 位 Hook 动态库路径 (ghost_hook.dll)
    #[arg(long)]
    dll_x64: Option<PathBuf>,

    /// 32 位 Hook 动态库路径
    #[arg(long)]
    dll_x86: Option<PathBuf>,

    /// 严格 DNS 防泄漏模式 (启用 Fake-IP 并阻断外部 UDP/53 及 QUIC)
    #[arg(long, default_value_t = true)]
    strict_dns: bool,

    /// 上游 SOCKS5 认证用户名
    #[arg(long)]
    username: Option<String>,

    /// 上游 SOCKS5 认证密码
    #[arg(long)]
    password: Option<String>,

    /// 路由分流规则预设 (smart / global / direct) 或 JSON 规则文件路径
    #[arg(long, default_value = "smart")]
    rules: String,
}

fn resolve_hook_dll(arch: Architecture, explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path);
        }
        anyhow::bail!("指定的动态库路径不存在: {:?}", path);
    }

    let dll_names = match arch {
        Architecture::X64 => ["shadow_hook.dll", "ghost_hook.dll"],
        Architecture::X86 => ["shadow_hook32.dll", "ghost_hook32.dll"],
        _ => anyhow::bail!("暂不支持对目标架构 {:?} 的自动 DLL 查找", arch),
    };

    // 1. 尝试在当前可执行文件同级目录及其 bin 子目录查找
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            for name in &dll_names {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Ok(candidate);
                }
                let bin_candidate = dir.join("bin").join(name);
                if bin_candidate.exists() {
                    return Ok(bin_candidate);
                }
            }
        }
    }

    // 2. 尝试在本地工作区、bin 目录与构建目标目录查找
    let mut candidates = Vec::new();
    for name in &dll_names {
        candidates.push(format!("bin\\{}", name));
        candidates.push(format!("target\\release\\{}", name));
        candidates.push(format!("target\\debug\\{}", name));
        if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
            candidates.push(format!("{}\\release\\{}", target_dir, name));
            candidates.push(format!("{}\\debug\\{}", target_dir, name));
        }
    }

    for c in &candidates {
        let p = Path::new(c);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    anyhow::bail!(
        "未找到适用于 {:?} 架构的 Hook 动态库，请使用 --dll-x64 或 --dll-x86 手动指定",
        arch
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!("Ghost Proxifier CLI 已启动");

    let upstream_addr: SocketAddr = args
        .proxy
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的上游代理地址 [{}]: {}", args.proxy, e))?;

    let listen_addr: SocketAddr = args
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的本地监听地址 [{}]: {}", args.listen, e))?;

    let proxy_auth = match (args.username, args.password) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };

    let relay_config = RelayConfig {
        listen_addr,
        upstream_proxy: upstream_addr,
        proxy_auth,
        strict_dns: args.strict_dns,
        handshake_timeout: None,
    };

    let router = match args.rules.to_lowercase().as_str() {
        "smart" => shadow_core::router::Router::preset_smart(),
        "global" | "global_proxy" => shadow_core::router::Router::preset_global_proxy(),
        "direct" | "direct_all" => shadow_core::router::Router::preset_direct_all(),
        path => {
            if let Ok(content) = std::fs::read_to_string(path) {
                serde_json::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("规则文件 JSON 格式错误: {}", e))?
            } else {
                anyhow::bail!("未知的路由预设或不存在的规则文件: {}", path);
            }
        }
    };

    let router = std::sync::Arc::new(std::sync::RwLock::new(router));
    let tracker = std::sync::Arc::new(shadow_core::session::SessionTracker::default());
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // 启动本地透明代理中继服务
    let bound_server = RelayServer::bind_with_components(
        relay_config,
        std::sync::Arc::new(shadow_core::relay::TrafficStats::default()),
        std::sync::Arc::clone(&router),
        std::sync::Arc::clone(&tracker),
    )
    .await?;
    let local_relay_addr = bound_server.local_addr();
    let stats = bound_server.stats();

    tokio::spawn(async move {
        if let Err(e) = bound_server.run(shutdown_rx).await {
            tracing::error!("本地透明中继运行异常: {}", e);
        }
    });

    tracing::info!("本地透明中继就绪: {}", local_relay_addr);
    tracing::info!("上游代理目标: {}", upstream_addr);
    tracing::info!("路由分流预设: {}", args.rules);
    tracing::info!("严格 DNS 防泄漏: {}", args.strict_dns);

    // 传递控制环境变量给被注入进程 (兼容 SHADOW_* 与历史 GHOST_*)
    let port_str = local_relay_addr.port().to_string();
    let dns_flag = if args.strict_dns { "1" } else { "0" };
    std::env::set_var("SHADOW_RELAY_PORT", &port_str);
    std::env::set_var("GHOST_RELAY_PORT", &port_str);
    std::env::set_var("SHADOW_STRICT_DNS", dns_flag);
    std::env::set_var("GHOST_STRICT_DNS", dns_flag);

    if let Some(target_exe) = args.target {
        tracing::info!("正在分析目标可执行文件: {:?}", target_exe);
        let arch = detect_architecture(&target_exe)?;
        tracing::info!("识别到目标架构: {:?}", arch);

        let explicit_dll = match arch {
            Architecture::X64 => args.dll_x64,
            Architecture::X86 => args.dll_x86,
            _ => None,
        };

        let dll_path = resolve_hook_dll(arch, explicit_dll)?;
        tracing::info!("选用注入动态库: {:?}", dll_path);

        let pid = spawn_and_inject_with_args(&target_exe, &dll_path, args.args.as_deref())?;
        tracing::info!("目标程序启动并注入成功，PID: {}", pid);

        tracing::info!("进程透明代理运行中，等待目标进程退出 (或按 Ctrl+C 终止)...");

        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                    | 0x0010_0000, // SYNCHRONIZE
                0,
                pid,
            )
        };

        if handle.is_null() {
            tokio::signal::ctrl_c().await?;
        } else {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let mut exit_code = 0u32;
                        let ok = unsafe {
                            windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code)
                        };
                        if ok != 0 && exit_code != 259 {
                            tracing::info!("目标程序已退出，退出代码: {}", exit_code);
                            break;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("收到 Ctrl+C 信号，正在退出代理...");
                        break;
                    }
                }
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        }
    } else {
        tracing::info!("未指定目标程序，作为中继代理守护运行中，按 Ctrl+C 退出...");
        tokio::signal::ctrl_c().await?;
    }

    tracing::info!("收到停止信号，正在平稳注销中继...");
    let _ = shutdown_tx.send(());

    tracing::info!(
        "本次会话累计统计: 上行发送 {} 字节, 下行接收 {} 字节",
        stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
        stats.bytes_received.load(std::sync::atomic::Ordering::Relaxed)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_args_defaults() {
        let args = Args::try_parse_from(["shadow-cli"]).unwrap();
        assert_eq!(args.proxy, "127.0.0.1:10808");
        assert_eq!(args.listen, "127.0.0.1:0");
        assert_eq!(args.rules, "smart");
        assert!(args.strict_dns);
        assert_eq!(args.target, None);
        assert_eq!(args.args, None);
        assert_eq!(args.username, None);
        assert_eq!(args.password, None);
    }

    #[test]
    fn test_cli_args_custom_values() {
        let args = Args::try_parse_from([
            "shadow-cli",
            "--target",
            "C:\\Windows\\System32\\cmd.exe",
            "--args",
            "/c dir",
            "--proxy",
            "192.168.1.1:7890",
            "--listen",
            "127.0.0.1:19090",
            "--strict-dns",
            "--rules",
            "global",
            "--username",
            "admin",
            "--password",
            "secret123",
        ])
        .unwrap();

        assert_eq!(args.target, Some(PathBuf::from("C:\\Windows\\System32\\cmd.exe")));
        assert_eq!(args.args.as_deref(), Some("/c dir"));
        assert_eq!(args.proxy, "192.168.1.1:7890");
        assert_eq!(args.listen, "127.0.0.1:19090");
        assert!(args.strict_dns);
        assert_eq!(args.rules, "global");
        assert_eq!(args.username.as_deref(), Some("admin"));
        assert_eq!(args.password.as_deref(), Some("secret123"));
    }
}
