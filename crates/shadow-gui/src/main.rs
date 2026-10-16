//! shadow-gui: ShadowProxy 图形桌面交互端
//!
//! 基于 Wry / Tao 原生 WebView 构建的高性能极简控制台，
//! 负责本地透明中继管理、双架构目标程序注入、拖拽捕获与实时流量看板。

#![windows_subsystem = "windows"]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::windows::WindowExtWindows,
    window::WindowBuilder,
};
use wry::{DragDropEvent, WebViewBuilder};

use shadow_core::protocol::TargetAddr;
use shadow_core::relay::{RelayConfig, RelayServer, TrafficStats};
use shadow_core::router::{RouteAction, RuleItem, RulePattern, Router};
use shadow_core::session::{SessionRecord, SessionTracker};
use shadow_injector::{detect_architecture, inject_existing_pid, spawn_and_inject_with_args, Architecture};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tokio::sync::broadcast;

mod icon_extractor;

#[derive(Debug)]
enum UserEvent {
    Ipc(String),
    Dropped(PathBuf),
    Tick,
    SystemSuspend,
    SystemResume,
    Log(String),
    TrayShow,
    TrayToggleRelay,
    TrayExit,
    UpdateCheckResult {
        silent: bool,
        success: bool,
        error: Option<String>,
        data: Option<serde_json::Value>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(tag = "cmd")]
enum IpcCommand {
    #[serde(rename = "get_state")]
    GetState,
    #[serde(rename = "browse_file")]
    BrowseFile,
    #[serde(rename = "start_relay")]
    StartRelay { proxy: String, strict_dns: bool },
    #[serde(rename = "stop_relay")]
    StopRelay,
    #[serde(rename = "launch_process")]
    LaunchProcess {
        target: String,
        args: Option<String>,
        proxy: Option<String>,
        strict_dns: Option<bool>,
    },
    #[serde(rename = "attach_process")]
    AttachProcess { pid: u32 },
    #[serde(rename = "list_system_processes")]
    ListSystemProcesses,
    #[serde(rename = "kill_process")]
    KillProcess { pid: u32 },
    #[serde(rename = "add_preset")]
    AddPreset {
        name: Option<String>,
        target: String,
        args: Option<String>,
    },
    #[serde(rename = "update_preset")]
    UpdatePreset {
        index: usize,
        name: String,
        target: String,
        args: String,
    },
    #[serde(rename = "delete_preset")]
    DeletePreset { index: usize },
    #[serde(rename = "add_rule")]
    AddRule {
        name: String,
        pattern_type: String,
        pattern_val: String,
        action: String,
    },
    #[serde(rename = "move_rule")]
    MoveRule { from: usize, to: usize },
    #[serde(rename = "import_rules")]
    ImportRules { json: String },
    #[serde(rename = "clear_rules")]
    ClearRules,
    #[serde(rename = "delete_rule")]
    DeleteRule { id: String },
    #[serde(rename = "toggle_rule")]
    ToggleRule { id: String, enabled: bool },
    #[serde(rename = "set_rule_preset")]
    SetRulePreset { preset: String },
    #[serde(rename = "clear_sessions")]
    ClearSessions,
    #[serde(rename = "ping_upstream")]
    PingUpstream { proxy: String },
    #[serde(rename = "set_proxy_config")]
    SetProxyConfig { proxy: String, strict_dns: bool },
    #[serde(rename = "window_ready")]
    WindowReady,
    #[serde(rename = "open_url")]
    OpenUrl { url: String },
    #[serde(rename = "download_and_install")]
    DownloadAndInstall { url: String, filename: String },
    #[serde(rename = "check_update")]
    CheckUpdate { silent: bool },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PresetItem {
    pub name: String,
    pub target: String,
    pub args: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    arch: String,
    running: bool,
    exit_code: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

struct TrackedProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    arch: String,
    handle: windows_sys::Win32::Foundation::HANDLE,
    running: bool,
    exit_code: u32,
    icon: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelayStatus {
    Offline,
    Online,
    Degraded,
}

impl RelayStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayStatus::Offline => "OFFLINE",
            RelayStatus::Online => "ONLINE",
            RelayStatus::Degraded => "DEGRADED",
        }
    }
}

#[derive(Serialize, Debug)]
struct FullState {
    app_version: String,
    relay_active: bool,
    relay_status: String,
    upstream_healthy: bool,
    relay_addr: Option<String>,
    upstream_proxy: String,
    strict_dns: bool,
    bytes_sent: u64,
    bytes_received: u64,
    speed_up_bps: u64,
    speed_down_bps: u64,
    processes: Vec<ProcessInfo>,
    presets: Vec<PresetItem>,
    rules: Vec<RuleItem>,
    sessions: Vec<SessionRecord>,
    last_log: Option<String>,
    ping_ms: Option<u64>,
}

struct ActiveRelay {
    shutdown_tx: broadcast::Sender<()>,
    _stats: Arc<TrafficStats>,
    local_addr: SocketAddr,
    health_rx: tokio::sync::watch::Receiver<(RelayStatus, Option<u64>)>,
    resume_notify: Arc<tokio::sync::Notify>,
}

fn presets_file_path() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(|appdata| {
        Path::new(&appdata).join("ShadowProxy").join("presets.json")
    })
}

fn rules_file_path() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(|appdata| {
        Path::new(&appdata).join("ShadowProxy").join("rules.json")
    })
}

fn config_file_path() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(|appdata| {
        Path::new(&appdata).join("ShadowProxy").join("config.json")
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AppConfig {
    upstream_proxy: String,
    strict_dns: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            upstream_proxy: "127.0.0.1:7897".to_string(),
            strict_dns: true,
        }
    }
}

struct AppState {
    rt: tokio::runtime::Runtime,
    relay: Option<ActiveRelay>,
    relay_port: Option<u16>,
    upstream_proxy: String,
    strict_dns: bool,
    processes: Vec<TrackedProcess>,
    presets: Vec<PresetItem>,
    router: Arc<RwLock<Router>>,
    tracker: Arc<SessionTracker>,
    last_log: Option<String>,
    ping_ms: Option<u64>,
}

impl AppState {
    fn load_presets() -> Vec<PresetItem> {
        if let Some(path) = presets_file_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(mut items) = serde_json::from_str::<Vec<PresetItem>>(&content) {
                        let mut updated = false;
                        for item in &mut items {
                            if item.icon.is_none() {
                                item.icon = icon_extractor::extract_icon_as_base64_png(&item.target);
                                if item.icon.is_some() {
                                    updated = true;
                                }
                            }
                        }
                        if updated {
                            if let Ok(json) = serde_json::to_string_pretty(&items) {
                                let _ = std::fs::write(&path, json);
                            }
                        }
                        return items;
                    }
                }
            }
        }

        let mut defaults = Vec::new();
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let ag_path = Path::new(&local_appdata)
                .join("Programs")
                .join("antigravity")
                .join("Antigravity.exe");
            if ag_path.exists() {
                let ag_target = ag_path.to_string_lossy().to_string();
                let icon = icon_extractor::extract_icon_as_base64_png(&ag_target);
                defaults.push(PresetItem {
                    name: "Antigravity (AI IDE)".to_string(),
                    target: ag_target,
                    args: "--no-proxy-server".to_string(),
                    icon,
                });
            }
        }
        let curl_target = "C:\\Windows\\System32\\curl.exe".to_string();
        let curl_icon = icon_extractor::extract_icon_as_base64_png(&curl_target);
        defaults.push(PresetItem {
            name: "curl.exe (连通性测速)".to_string(),
            target: curl_target,
            args: "https://api.ipify.org -v".to_string(),
            icon: curl_icon,
        });

        if let Some(path) = presets_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&defaults) {
                let _ = std::fs::write(&path, json);
            }
        }

        defaults
    }

    fn save_presets(&self) {
        if let Some(path) = presets_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&self.presets) {
                let _ = std::fs::write(&path, json);
            }
        }
    }

    fn load_rules() -> Router {
        if let Some(path) = rules_file_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(r) = serde_json::from_str::<Router>(&content) {
                        return r;
                    }
                }
            }
        }
        let default_router = Router::preset_smart();
        if let Some(path) = rules_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&default_router) {
                let _ = std::fs::write(&path, json);
            }
        }
        default_router
    }

    fn save_rules(&self) {
        if let Some(path) = rules_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let router = self.router.read().unwrap();
            if let Ok(json) = serde_json::to_string_pretty(&*router) {
                let _ = std::fs::write(&path, json);
            }
        }
    }

    fn ping_upstream(&mut self, proxy_str: &str) {
        let proxy_addr = match proxy_str.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                self.last_log = Some(format!("[PING] 代理地址格式无效: {}", e));
                self.ping_ms = None;
                return;
            }
        };

        let start = std::time::Instant::now();
        let res = self.rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(3000), async {
                let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
                let target = TargetAddr::Ip("1.1.1.1:53".parse().unwrap());
                shadow_core::protocol::socks5_connect(&mut stream, &target, None).await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
        });

        match res {
            Ok(Ok(())) => {
                let ms = start.elapsed().as_millis() as u64;
                self.ping_ms = Some(ms);
                self.last_log = Some(format!("[PING] 上游代理握手成功，延迟: {} ms", ms));
            }
            Ok(Err(e)) => {
                self.ping_ms = None;
                self.last_log = Some(format!("[PING] 代理连接失败: {}", e));
            }
            Err(_) => {
                self.ping_ms = None;
                self.last_log = Some("[PING] 代理连接超时 (3000ms)".to_string());
            }
        }
    }

    fn load_config() -> AppConfig {
        if let Some(path) = config_file_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = serde_json::from_str::<AppConfig>(&content) {
                        return cfg;
                    }
                }
            }
        }
        let def = AppConfig::default();
        if let Some(path) = config_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&def) {
                let _ = std::fs::write(&path, json);
            }
        }
        def
    }

    fn save_config(&self) {
        if let Some(path) = config_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let cfg = AppConfig {
                upstream_proxy: self.upstream_proxy.clone(),
                strict_dns: self.strict_dns,
            };
            if let Ok(json) = serde_json::to_string_pretty(&cfg) {
                let tmp_path = path.with_extension("json.tmp");
                if std::fs::write(&tmp_path, &json).is_ok() {
                    let _ = std::fs::rename(&tmp_path, &path);
                }
            }
        }
    }

    fn new() -> anyhow::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let cfg = Self::load_config();
        let presets = Self::load_presets();
        let router = Arc::new(RwLock::new(Self::load_rules()));
        let tracker = Arc::new(SessionTracker::new(200));

        Ok(Self {
            rt,
            relay: None,
            relay_port: None,
            upstream_proxy: cfg.upstream_proxy,
            strict_dns: cfg.strict_dns,
            processes: Vec::new(),
            presets,
            router,
            tracker,
            last_log: Some("[SYS] 系统就绪，等待操作".to_string()),
            ping_ms: None,
        })
    }

    fn start_relay(
        &mut self,
        proxy_str: &str,
        strict_dns: bool,
    ) -> Result<SocketAddr, String> {
        // 1. 前置参数校验，严禁在校验前破坏性关闭已有运行中的中继
        let (upstream_is_http, clean_proxy_str) = if let Some(stripped) = proxy_str.strip_prefix("http://") {
            (true, stripped)
        } else if let Some(stripped) = proxy_str.strip_prefix("socks5://") {
            (false, stripped)
        } else {
            (false, proxy_str)
        };

        let upstream_proxy: SocketAddr = clean_proxy_str
            .parse()
            .map_err(|e| format!("上游代理地址无效: {}", e))?;

        // 2. 停止旧中继
        self.stop_relay();

        // 3. 优先复用此前固定的本地监听端口，杜绝端口漂移导致已注入目标进程全面断网
        let listen_addr: SocketAddr = if let Some(port) = self.relay_port {
            SocketAddr::from(([127, 0, 0, 1], port))
        } else {
            "127.0.0.1:0".parse().unwrap()
        };

        let config = RelayConfig {
            listen_addr,
            upstream_proxy,
            upstream_is_http,
            proxy_auth: None,
            strict_dns,
            dns_over_tcp_server: Some("223.5.5.5:53".parse().unwrap()),
            handshake_timeout: None,
        };

        let bound = self
            .rt
            .block_on(RelayServer::bind_with_components(
                config,
                Arc::new(TrafficStats::default()),
                Arc::clone(&self.router),
                Arc::clone(&self.tracker),
            ))
            .map_err(|e| format!("绑定本地透明中继失败: {}", e))?;

        let local_addr = bound.local_addr();
        self.relay_port = Some(local_addr.port());
        let stats = bound.stats();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        self.rt.spawn(async move {
            let _ = bound.run(shutdown_rx).await;
        });

        let port_str = local_addr.port().to_string();
        let dns_flag = if strict_dns { "1" } else { "0" };
        std::env::set_var("SHADOW_RELAY_PORT", &port_str);
        std::env::set_var("GHOST_RELAY_PORT", &port_str);
        std::env::set_var("SHADOW_STRICT_DNS", dns_flag);
        std::env::set_var("GHOST_STRICT_DNS", dns_flag);

        // 4. 前置同步快速探活 (800ms) 决定启动初始健康状态，彻底杜绝虚假 ONLINE
        let initial_probe = self.rt.block_on(async {
            shadow_core::check_upstream_health_auto(
                upstream_proxy,
                upstream_is_http,
                None,
                std::time::Duration::from_millis(800),
            )
            .await
        });

        let (init_status, init_ping) = match initial_probe {
            Ok(dur) => (RelayStatus::Online, Some(dur.as_millis() as u64)),
            Err(_) => (RelayStatus::Degraded, None),
        };

        let (health_tx, health_rx) = tokio::sync::watch::channel((init_status, init_ping));
        let mut health_shutdown_rx = shutdown_tx.subscribe();
        let resume_notify = Arc::new(tokio::sync::Notify::new());
        let resume_rx = Arc::clone(&resume_notify);

        // 5. 启动后台健康心跳伴生协程 (每 2.5s 探活一次，并支持系统唤醒即时探活自愈)
        let probe_proxy = upstream_proxy;
        let probe_is_http = upstream_is_http;
        self.rt.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(2500));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let res = match shadow_core::check_upstream_health_auto(
                            probe_proxy,
                            probe_is_http,
                            None,
                            std::time::Duration::from_millis(800),
                        )
                        .await
                        {
                            Ok(dur) => (RelayStatus::Online, Some(dur.as_millis() as u64)),
                            Err(_) => (RelayStatus::Degraded, None),
                        };

                        if health_tx.send(res).is_err() {
                            break;
                        }
                    }
                    _ = resume_rx.notified() => {
                        // 系统休眠唤醒后，连续快速探测 3 次（每次间隔 1 秒），以便在上游代理就绪的第一时间自愈恢复
                        for _ in 0..3 {
                            let res = match shadow_core::check_upstream_health_auto(
                                probe_proxy,
                                probe_is_http,
                                None,
                                std::time::Duration::from_millis(800),
                            )
                            .await
                            {
                                Ok(dur) => (RelayStatus::Online, Some(dur.as_millis() as u64)),
                                Err(_) => (RelayStatus::Degraded, None),
                            };
                            let is_online = res.0 == RelayStatus::Online;
                            let _ = health_tx.send(res);
                            if is_online {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                        }
                    }
                    _ = health_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        self.relay = Some(ActiveRelay {
            shutdown_tx,
            _stats: stats,
            local_addr,
            health_rx,
            resume_notify,
        });
        self.upstream_proxy = proxy_str.to_string();
        self.strict_dns = strict_dns;
        self.save_config();

        if init_status == RelayStatus::Online {
            let ms_str = init_ping.map(|m| format!(" ({} ms)", m)).unwrap_or_default();
            self.last_log = Some(format!(
                "[RELAY] 本地透明中继已启动在 {}, 上游代理握手正常{}",
                local_addr, ms_str
            ));
        } else {
            self.last_log = Some(format!(
                "[WARN] 本地透明中继已启动在 {}, 但上游代理 ({}) 无法连通，请确认代理软件已启动！",
                local_addr, upstream_proxy
            ));
        }

        Ok(local_addr)
    }

    fn stop_relay(&mut self) {
        if let Some(active) = self.relay.take() {
            let _ = active.shutdown_tx.send(());
            self.last_log = Some("[RELAY] 本地透明中继已停止".to_string());
        }
    }

    fn handle_system_resume(&mut self) {
        self.last_log = Some("[SYS] 检测到系统休眠恢复，正在执行网络自愈与探活...".to_string());
        // 1. 清理休眠前挂起的陈旧会话
        self.tracker.clear();
        self.update_process_statuses();

        // 2. 检查本地监听端口是否仍然活跃，若因休眠被系统关闭则自动平滑拉起
        if let Some(port) = self.relay_port {
            if self.relay.is_some() {
                let check_addr = SocketAddr::from(([127, 0, 0, 1], port));
                let is_open = std::net::TcpStream::connect_timeout(
                    &check_addr,
                    std::time::Duration::from_millis(80),
                )
                .is_ok();

                if !is_open {
                    let proxy = self.upstream_proxy.clone();
                    let dns = self.strict_dns;
                    let _ = self.start_relay(&proxy, dns);
                    self.last_log = Some(format!(
                        "[RELAY] 唤醒后检测到本地端口 {} 异常关闭，已自动平滑自愈重启中继",
                        port
                    ));
                    return;
                }
            }
        }

        // 3. 通知后台健康探活协程立即连续探测
        if let Some(ref r) = self.relay {
            r.resume_notify.notify_waiters();
        }
    }
}

fn resolve_target_executable(input: &str) -> Result<PathBuf, String> {
    let clean = input.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() {
        return Err("请输入或选择目标程序可执行文件路径".to_string());
    }

    let p = PathBuf::from(clean);
    if p.exists() {
        if let Some((real_exe, _)) = shadow_injector::resolve_shortcut(&p) {
            return Ok(real_exe);
        }
        return Ok(p);
    }

    // 若不是绝对路径，尝试在 Windows System32、当前工作目录及 PATH 环境变量中检索
    if p.is_relative() {
        if let Ok(sys_root) = std::env::var("SystemRoot") {
            let sys32_candidate = Path::new(&sys_root).join("System32").join(clean);
            if sys32_candidate.exists() {
                if let Some((real_exe, _)) = shadow_injector::resolve_shortcut(&sys32_candidate) {
                    return Ok(real_exe);
                }
                return Ok(sys32_candidate);
            }
        }

        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(clean);
                if candidate.exists() {
                    if let Some((real_exe, _)) = shadow_injector::resolve_shortcut(&candidate) {
                        return Ok(real_exe);
                    }
                    return Ok(candidate);
                }
            }
        }
    }

    Err(format!("目标程序路径不存在: {}", clean))
}

fn pick_executable_file(owner: windows_sys::Win32::Foundation::HWND) -> Option<PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OPENFILENAMEW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST,
    };

    let mut file_buf = [0u16; 1024];
    let filter: Vec<u16> = "应用程序与快捷方式 (*.exe;*.lnk)\0*.exe;*.lnk\0可执行程序 (*.exe)\0*.exe\0快捷方式 (*.lnk)\0*.lnk\0所有文件 (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();

    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file_buf.as_mut_ptr();
    ofn.nMaxFile = file_buf.len() as u32;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    let success = unsafe { GetOpenFileNameW(&mut ofn) };
    if success != 0 {
        let len = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
        let path_str = String::from_utf16_lossy(&file_buf[..len]);
        Some(PathBuf::from(path_str))
    } else {
        None
    }
}

fn find_existing_pids_by_name(exe_name: &str) -> Vec<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    let mut pids = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return pids;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case(exe_name) {
                    pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        windows_sys::Win32::Foundation::CloseHandle(snap);
    }
    pids
}

impl AppState {
    fn launch_process(
        &mut self,
        target_str: &str,
        args_opt: Option<&str>,
    ) -> Result<u32, String> {
        let path = resolve_target_executable(target_str)?;

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let existing = find_existing_pids_by_name(&file_name);
        if !existing.is_empty() {
            self.last_log = Some(format!(
                "[警告] 发现已有运行中的 {} 实例 (PID: {:?})！建议先退出旧实例再启动，以确保全量劫持流量。",
                file_name, existing
            ));
        }

        // 若中继未启动，则自动按当前配置启动中继
        if self.relay.is_none() {
            let proxy = self.upstream_proxy.clone();
            let dns = self.strict_dns;
            self.start_relay(&proxy, dns)?;
        }

        // 检查当前中继是否处于降级状态 (上游未启动/不可达)
        let is_upstream_degraded = if let Some(ref r) = self.relay {
            let (st, _) = *r.health_rx.borrow();
            st == RelayStatus::Degraded
        } else {
            false
        };

        if is_upstream_degraded {
            self.last_log = Some(format!(
                "[WARN] 警告：上游代理 ({}) 尚未就绪！已注入进程 {:?} 的网络请求可能失败，请尽快启动代理软件",
                self.upstream_proxy, file_name
            ));
        }

        let arch = detect_architecture(&path)
            .map_err(|e| format!("分析目标 PE 架构失败: {}", e))?;

        let dll_path = resolve_hook_dll(arch)
            .map_err(|e| format!("定位 Hook 动态库失败: {}", e))?;

        let args_clean = args_opt.filter(|s| !s.trim().is_empty());
        let pid = spawn_and_inject_with_args(&path, &dll_path, args_clean)
            .map_err(|e| format!("启动并注入目标程序失败: {}", e))?;

        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                    | windows_sys::Win32::System::Threading::PROCESS_TERMINATE
                    | 0x0010_0000, // SYNCHRONIZE
                0,
                pid,
            )
        };

        let icon = icon_extractor::extract_icon_as_base64_png(&path);
        self.processes.push(TrackedProcess {
            pid,
            parent_pid: None,
            name: file_name,
            path: target_str.to_string(),
            arch: format!("{:?}", arch),
            handle,
            running: true,
            exit_code: 0,
            icon,
        });

        self.last_log = Some(format!(
            "[INJECT] 成功注入 {:?} (PID: {}, 架构: {:?})",
            target_str, pid, arch
        ));

        Ok(pid)
    }

    fn kill_process(&mut self, pid: u32) {
        for p in &mut self.processes {
            if p.pid == pid && p.running {
                if !p.handle.is_null() {
                    unsafe {
                        windows_sys::Win32::System::Threading::TerminateProcess(
                            p.handle, 1,
                        );
                    }
                }
                p.running = false;
                p.exit_code = 1;
                self.last_log = Some(format!("[PROC] 已终止 PID {}", pid));
                break;
            }
        }
    }

    fn attach_process(&mut self, pid: u32) -> Result<(), String> {
        if self.processes.iter().any(|p| p.pid == pid && p.running) {
            return Err(format!("进程 PID {} 已在托管列表中", pid));
        }

        use windows_sys::Win32::System::Threading::{
            OpenProcess, IsWow64Process, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE
        };
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return Err(format!("无法打开目标进程 PID {} (可能权限不足或进程已退出)", pid));
        }

        let mut is_wow64: windows_sys::Win32::Foundation::BOOL = 0;
        let ok = unsafe { IsWow64Process(h, &mut is_wow64) };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(h) };
        if ok == 0 {
            return Err(format!("查询进程 PID {} 架构失败", pid));
        }

        let arch = if is_wow64 != 0 {
            Architecture::X86
        } else {
            Architecture::X64
        };

        let dll_path = resolve_hook_dll(arch)
            .map_err(|e| format!("未找到对应架构 Hook 动态库: {}", e))?;

        // 注入目标进程
        inject_existing_pid(pid, &dll_path)
            .map_err(|e| format!("向进程 PID {} 附加注入失败: {}", pid, e))?;

        // 获取进程名
        let proc_name = list_system_processes()
            .into_iter()
            .find(|p| p.pid == pid)
            .map(|p| p.name)
            .unwrap_or_else(|| format!("PID:{}", pid));

        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, 0, pid)
        };

        self.processes.push(TrackedProcess {
            pid,
            parent_pid: None,
            name: proc_name.clone(),
            path: "".to_string(),
            arch: format!("{:?}", arch),
            handle,
            running: true,
            exit_code: 0,
            icon: None,
        });

        self.last_log = Some(format!("[INJECT] 成功附加到运行中进程 [{}] (PID: {})", proc_name, pid));
        Ok(())
    }

    fn update_preset(&mut self, index: usize, name: String, target: String, args: String) {
        if let Some(p) = self.presets.get_mut(index) {
            p.name = name;
            p.target = target;
            p.args = args;
            self.save_presets();
            self.last_log = Some("[PRESET] 常用快捷预设已更新".to_string());
        }
    }

    fn update_process_statuses(&mut self) {
        // 1. 检查已有跟踪进程的存活状态
        for p in &mut self.processes {
            if p.running && !p.handle.is_null() {
                let mut exit_code = 0u32;
                let ok = unsafe {
                    windows_sys::Win32::System::Threading::GetExitCodeProcess(
                        p.handle,
                        &mut exit_code,
                    )
                };
                if ok != 0 && exit_code != 259 {
                    p.running = false;
                    p.exit_code = exit_code;
                    unsafe {
                        windows_sys::Win32::Foundation::CloseHandle(p.handle);
                    }
                    p.handle = core::ptr::null_mut();
                    self.last_log = Some(format!(
                        "[PROC] 进程 {} (PID: {}) 退出，代码: {}",
                        p.name, p.pid, exit_code
                    ));
                }
            }
        }

        // 2. 递归扫描当前活跃进程树下的所有子进程 (如 Antigravity 派生的 LanguageServer、Utility/Network 进程)
        let active_pids: Vec<u32> = self
            .processes
            .iter()
            .filter(|p| p.running)
            .map(|p| p.pid)
            .collect();

        if !active_pids.is_empty() {
            let children = scan_child_processes(&active_pids);
            let dll_x64 = resolve_hook_dll(Architecture::X64).ok();

            for (child_pid, parent_pid, child_name) in children {
                if !self.processes.iter().any(|p| p.pid == child_pid) {
                    // 确保子进程被注入最新的 Hook 动态库
                    if let Some(ref dll_path) = dll_x64 {
                        let _ = inject_existing_pid(child_pid, dll_path);
                    }

                    let handle = unsafe {
                        windows_sys::Win32::System::Threading::OpenProcess(
                            windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                                | windows_sys::Win32::System::Threading::PROCESS_TERMINATE
                                | 0x0010_0000,
                            0,
                            child_pid,
                        )
                    };

                    let icon = self
                        .processes
                        .iter()
                        .find(|p| p.pid == parent_pid)
                        .and_then(|p| p.icon.clone());

                    self.processes.push(TrackedProcess {
                        pid: child_pid,
                        parent_pid: Some(parent_pid),
                        name: child_name.clone(),
                        path: child_name.clone(),
                        arch: "X64".to_string(),
                        handle,
                        running: true,
                        exit_code: 0,
                        icon,
                    });

                    self.last_log = Some(format!(
                        "[INJECT] 自动纳管并注入子进程 {} (PID: {}, 父PID: {})",
                        child_name, child_pid, parent_pid
                    ));
                }
            }
        }
    }

    fn get_full_state(&self) -> FullState {
        let (speed_up_bps, speed_down_bps, total_up, total_down) = self.tracker.speed_and_totals();
        let (bytes_sent, bytes_received) = if self.relay.is_some() {
            (total_up, total_down)
        } else {
            (0, 0)
        };

        let procs = self
            .processes
            .iter()
            .map(|p| ProcessInfo {
                pid: p.pid,
                parent_pid: p.parent_pid,
                name: p.name.clone(),
                path: p.path.clone(),
                arch: p.arch.clone(),
                running: p.running,
                exit_code: p.exit_code,
                icon: p.icon.clone(),
            })
            .collect();

        let rules = self.router.read().unwrap().rules.clone();
        let sessions = self.tracker.list_sessions(60);

        let (relay_status, dynamic_ping) = if let Some(ref r) = self.relay {
            let (st, p) = *r.health_rx.borrow();
            (st.as_str().to_string(), p)
        } else {
            ("OFFLINE".to_string(), None)
        };

        let upstream_healthy = relay_status == "ONLINE";
        let ping_ms = dynamic_ping.or(self.ping_ms);

        FullState {
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            relay_active: self.relay.is_some(),
            relay_status,
            upstream_healthy,
            relay_addr: self.relay.as_ref().map(|r| r.local_addr.to_string()),
            upstream_proxy: self.upstream_proxy.clone(),
            strict_dns: self.strict_dns,
            bytes_sent,
            bytes_received,
            speed_up_bps,
            speed_down_bps,
            processes: procs,
            presets: self.presets.clone(),
            rules,
            sessions,
            last_log: self.last_log.clone(),
            ping_ms,
        }
    }
}

fn scan_child_processes(root_pids: &[u32]) -> Vec<(u32, u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut children = Vec::new();
    if root_pids.is_empty() {
        return children;
    }

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return children;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut all_processes: Vec<(u32, u32, String)> = Vec::new();
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let null_pos = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..null_pos]);
                all_processes.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);

        let mut active_parents = std::collections::HashSet::new();
        for &pid in root_pids {
            active_parents.insert(pid);
        }

        let mut added = true;
        while added {
            added = false;
            for (pid, parent_pid, name) in &all_processes {
                if active_parents.contains(parent_pid) && !active_parents.contains(pid) {
                    active_parents.insert(*pid);
                    children.push((*pid, *parent_pid, name.clone()));
                    added = true;
                }
            }
        }
    }

    children
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemProcessItem {
    pub pid: u32,
    pub name: String,
}

fn list_system_processes() -> Vec<SystemProcessItem> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut result = Vec::new();
    let my_pid = std::process::id();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid > 4 && pid != my_pid {
                    let null_pos = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..null_pos]);
                    result.push(SystemProcessItem { pid, name });
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    result.sort_by_key(|a| a.name.to_ascii_lowercase());
    result
}

fn format_curl_proxy(proxy_str: &str) -> Option<String> {
    let trimmed = proxy_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Some(trimmed.to_string())
    } else if trimmed.starts_with("socks5://") || trimmed.starts_with("socks5h://") {
        let addr = trimmed
            .trim_start_matches("socks5://")
            .trim_start_matches("socks5h://");
        Some(format!("socks5h://{}", addr))
    } else {
        Some(format!("socks5h://{}", trimmed))
    }
}

fn check_github_update(upstream_proxy: &str) -> Result<serde_json::Value, String> {
    let proxy_arg = format_curl_proxy(upstream_proxy);

    let run_curl_api = |proxy: Option<&str>| -> Result<serde_json::Value, String> {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("curl.exe");
        cmd.args([
            "-s",
            "--fail",
            "--connect-timeout",
            "8",
            "--max-time",
            "15",
            "-H",
            "Accept: application/vnd.github.v3+json",
            "-H",
            "User-Agent: ShadowProxy-App",
        ]);
        if let Some(p) = proxy {
            cmd.arg("--proxy").arg(p);
        }
        cmd.arg("https://api.github.com/repos/jnnmia/shadow-proxy/releases/latest");
        cmd.creation_flags(0x08000000);

        let output = cmd.output().map_err(|e| format!("执行 curl 失败: {}", e))?;
        if !output.status.success() {
            return Err(format!("curl 退出代码: {:?}", output.status.code()));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|e| format!("解析 GitHub 响应失败: {}", e))
    };

    let run_curl_redirect = |proxy: Option<&str>| -> Result<serde_json::Value, String> {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("curl.exe");
        cmd.args([
            "-s",
            "-I",
            "--connect-timeout",
            "8",
            "--max-time",
            "15",
            "-H",
            "User-Agent: ShadowProxy-App",
        ]);
        if let Some(p) = proxy {
            cmd.arg("--proxy").arg(p);
        }
        cmd.arg("https://github.com/jnnmia/shadow-proxy/releases/latest");
        cmd.creation_flags(0x08000000);

        let output = cmd.output().map_err(|e| format!("执行 curl 失败: {}", e))?;
        let headers = String::from_utf8_lossy(&output.stdout);
        for line in headers.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("location:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let target_url = parts[1].trim();
                    if let Some(tag) = target_url.split("/tag/").nth(1) {
                        let clean_tag = tag.trim().to_string();
                        let setup_name = format!("ShadowProxy-Setup-{}.exe", clean_tag);
                        let download_url = format!(
                            "https://github.com/jnnmia/shadow-proxy/releases/download/{}/{}",
                            clean_tag, setup_name
                        );
                        return Ok(serde_json::json!({
                            "tag_name": clean_tag,
                            "name": clean_tag,
                            "html_url": target_url,
                            "body": "可前往 GitHub Releases 页面查看完整版本更新说明。",
                            "published_at": null,
                            "assets": [
                                {
                                    "name": setup_name,
                                    "browser_download_url": download_url
                                }
                            ]
                        }));
                    }
                }
            }
        }
        Err("未能从 GitHub Releases 重定向解析出最新版本".to_string())
    };

    if let Some(ref p) = proxy_arg {
        if let Ok(val) = run_curl_api(Some(p)) {
            return Ok(val);
        }
        if p.starts_with("socks5h://") {
            let http_proxy = format!("http://{}", p.trim_start_matches("socks5h://"));
            if let Ok(val) = run_curl_api(Some(&http_proxy)) {
                return Ok(val);
            }
        }
    }

    if let Ok(val) = run_curl_api(None) {
        return Ok(val);
    }

    if let Some(ref p) = proxy_arg {
        if let Ok(val) = run_curl_redirect(Some(p)) {
            return Ok(val);
        }
        if p.starts_with("socks5h://") {
            let http_proxy = format!("http://{}", p.trim_start_matches("socks5h://"));
            if let Ok(val) = run_curl_redirect(Some(&http_proxy)) {
                return Ok(val);
            }
        }
    }

    if let Ok(val) = run_curl_redirect(None) {
        return Ok(val);
    }

    Err("无法连接至 GitHub 获取更新，请检查网络或上游代理配置".to_string())
}

fn resolve_hook_dll(arch: Architecture) -> anyhow::Result<PathBuf> {
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

    // 2. 尝试在本地工作区、bin 目录与构建缓存目录查找
    let mut candidates = Vec::new();
    for name in &dll_names {
        candidates.push(format!("bin\\{}", name));
        candidates.push(format!("target\\release\\{}", name));
        candidates.push(format!("target\\debug\\{}", name));
        if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
            candidates.push(format!("{}\\{}\\{}", target_dir, "release", name));
            candidates.push(format!("{}\\{}\\{}", target_dir, "debug", name));
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            candidates.push(format!("{}\\.cargo_target\\shadow-proxy\\release\\{}", home, name));
            candidates.push(format!("{}\\.cargo_target\\shadow-proxy\\debug\\{}", home, name));
            candidates.push(format!("{}\\.cargo_target\\ghost-proxifier\\release\\{}", home, name));
            candidates.push(format!("{}\\.cargo_target\\ghost-proxifier\\debug\\{}", home, name));
        }
    }

    for c in &candidates {
        let p = Path::new(c);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    anyhow::bail!("未找到适用于 {:?} 架构的 Hook 动态库", arch)
}

fn show_win32_error_box(title: &str, msg: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let title_w: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let msg_w: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(0 as _, msg_w.as_ptr(), title_w.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

fn main() {
    if let Err(e) = run_app() {
        let err_text = format!("{:#}", e);
        show_win32_error_box("ShadowProxy 启动失败", &err_text);
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let log_dir = Path::new(&appdata).join("ShadowProxy");
            let _ = std::fs::create_dir_all(&log_dir);
            let _ = std::fs::write(log_dir.join("launch_error.log"), &err_text);
        }
        std::process::exit(1);
    }
}

static IS_DOWNLOADING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn run_app() -> anyhow::Result<()> {
    let log_step = |step: &str| {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let log_dir = Path::new(&appdata).join("ShadowProxy");
            let _ = std::fs::create_dir_all(&log_dir);
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_dir.join("startup.log")) {
                let _ = writeln!(f, "[PID {}] {}", std::process::id(), step);
            }
        }
    };

    log_step("1. run_app started");

    // 创建系统命名互斥体，供 Inno Setup 安装包检测与单实例识别
    let mutex_name: Vec<u16> = "Global\\ShadowProxy_App_Mutex_2026\0".encode_utf16().collect();
    let _app_mutex = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexW(
            core::ptr::null(),
            0,
            mutex_name.as_ptr(),
        )
    };

    // 注册全局 Panic 钩子，发生未捕获 Panic 时写入崩溃日志并弹出 Windows 错误对话框，杜绝无感静默闪退
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("ShadowProxy 发生未捕获异常:\n{}", info);
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let log_dir = Path::new(&appdata).join("ShadowProxy");
            let _ = std::fs::create_dir_all(&log_dir);
            let _ = std::fs::write(log_dir.join("crash.log"), &msg);
        }
        show_win32_error_box("ShadowProxy 致命异常", &msg);
    }));

    // 单实例与僵尸进程自愈守护：
    // 1. 检查是否存在已有窗口
    let title_w: Vec<u16> = "ShadowProxy - 极简透明代理控制台\0".encode_utf16().collect();
    let existing_hwnd = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(std::ptr::null(), title_w.as_ptr())
    };
    if !existing_hwnd.is_null() {
        log_step("2. Existing window found, activating");
        unsafe {
            use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SetForegroundWindow, SW_RESTORE};
            ShowWindow(existing_hwnd, SW_RESTORE);
            SetForegroundWindow(existing_hwnd);
        }
        return Ok(());
    }

    // 2. 若无可见窗口但存在残留僵尸进程，彻底终止以释放 WebView2 用户目录锁
    let my_pid = std::process::id();
    let existing_pids = find_existing_pids_by_name("shadow-gui.exe");
    let mut killed_any = false;
    for pid in existing_pids {
        if pid != my_pid {
            log_step(&format!("3. Terminating zombie process PID {}", pid));
            unsafe {
                use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
                use windows_sys::Win32::Foundation::CloseHandle;
                let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if !h.is_null() {
                    let _ = TerminateProcess(h, 1);
                    CloseHandle(h);
                    killed_any = true;
                }
            }
        }
    }
    if killed_any {
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    // 性能优化：强制将 WebView2 用户数据与渲染缓存目录置于本地高速 SSD (%LOCALAPPDATA%)，
    // 彻底根除在网络共享盘 (SMB/局域网盘) 或外部存储运行时 Chromium 的网络 I/O 锁争用与启动极慢卡顿
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let webview_cache = Path::new(&local_appdata).join("ShadowProxy").join("webview2");
        let _ = std::fs::create_dir_all(&webview_cache);
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &webview_cache);
    }

    log_step("4. Building EventLoop and Window");
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("ShadowProxy - 极简透明代理控制台")
        .with_inner_size(LogicalSize::new(960.0, 680.0))
        .with_min_inner_size(LogicalSize::new(820.0, 520.0))
        .with_visible(false)
        .build(&event_loop)?;

    let hwnd = window.hwnd() as windows_sys::Win32::Foundation::HWND;

    // 设置窗口标题栏与任务栏大/小专属图标，并初始化系统托盘图标
    let mut nid: windows_sys::Win32::UI::Shell::NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTSIZE,
            WM_SETICON,
        };
        let h_instance =
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null());
        let h_icon = LoadImageW(h_instance, 1 as _, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
        if !h_icon.is_null() {
            SendMessageW(hwnd, WM_SETICON, ICON_BIG as _, h_icon as _);
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL as _, h_icon as _);

            use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIM_ADD, NIF_ICON, NIF_MESSAGE, NIF_TIP};
            const WM_USER: u32 = 0x0400;
            const WM_TRAYICON: u32 = WM_USER + 100;
            nid.cbSize = std::mem::size_of::<windows_sys::Win32::UI::Shell::NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1001;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = h_icon;
            let tip: Vec<u16> = "ShadowProxy - 进程级透明代理\0".encode_utf16().collect();
            let c_len = tip.len().min(nid.szTip.len());
            nid.szTip[..c_len].copy_from_slice(&tip[..c_len]);
            Shell_NotifyIconW(NIM_ADD, &nid);
        }
    }

    let proxy = event_loop.create_proxy();
    let proxy_ipc = proxy.clone();
    let proxy_drop = proxy.clone();

    // 监听系统广播 (电源状态 + 系统托盘消息)
    unsafe {
        #[link(name = "comctl32")]
        extern "system" {
            fn SetWindowSubclass(
                hWnd: windows_sys::Win32::Foundation::HWND,
                pfnSubclass: unsafe extern "system" fn(
                    windows_sys::Win32::Foundation::HWND,
                    u32,
                    usize,
                    isize,
                    usize,
                    usize,
                ) -> isize,
                uIdSubclass: usize,
                dwRefData: usize,
            ) -> windows_sys::Win32::Foundation::BOOL;

            fn DefSubclassProc(
                hWnd: windows_sys::Win32::Foundation::HWND,
                uMsg: u32,
                wParam: usize,
                lParam: isize,
            ) -> isize;
        }

        unsafe extern "system" fn power_subclass_proc(
            hwnd: windows_sys::Win32::Foundation::HWND,
            msg: u32,
            wparam: usize,
            lparam: isize,
            _id: usize,
            ref_data: usize,
        ) -> isize {
            const WM_POWERBROADCAST: u32 = 0x0218;
            const PBT_APMSUSPEND: usize = 0x0004;
            const PBT_APMRESUMEAUTOMATIC: usize = 0x0012;
            const PBT_APMRESUMESUSPEND: usize = 0x0007;

            const WM_USER: u32 = 0x0400;
            const WM_TRAYICON: u32 = WM_USER + 100;
            const WM_RBUTTONUP: usize = 0x0205;
            const WM_LBUTTONDBLCLK: usize = 0x0203;
            const WM_LBUTTONUP: usize = 0x0202;

            if msg == WM_POWERBROADCAST {
                let proxy_ref = &*(ref_data as *const tao::event_loop::EventLoopProxy<UserEvent>);
                if wparam == PBT_APMSUSPEND {
                    let _ = proxy_ref.send_event(UserEvent::SystemSuspend);
                } else if wparam == PBT_APMRESUMEAUTOMATIC || wparam == PBT_APMRESUMESUSPEND {
                    let _ = proxy_ref.send_event(UserEvent::SystemResume);
                }
            } else if msg == WM_TRAYICON {
                let proxy_ref = &*(ref_data as *const tao::event_loop::EventLoopProxy<UserEvent>);
                let evt = lparam as usize;
                if evt == WM_LBUTTONDBLCLK || evt == WM_LBUTTONUP {
                    let _ = proxy_ref.send_event(UserEvent::TrayShow);
                } else if evt == WM_RBUTTONUP {
                    use windows_sys::Win32::UI::WindowsAndMessaging::{
                        CreatePopupMenu, AppendMenuW, TrackPopupMenu, DestroyMenu,
                        GetCursorPos, SetForegroundWindow,
                        MF_STRING, TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD,
                    };
                    let mut pt: windows_sys::Win32::Foundation::POINT = std::mem::zeroed();
                    GetCursorPos(&mut pt);
                    SetForegroundWindow(hwnd);
                    let hmenu = CreatePopupMenu();
                    let m_show: Vec<u16> = "打开主界面\0".encode_utf16().collect();
                    let m_toggle: Vec<u16> = "启动/停止中继\0".encode_utf16().collect();
                    let m_exit: Vec<u16> = "退出程序\0".encode_utf16().collect();
                    AppendMenuW(hmenu, MF_STRING, 1, m_show.as_ptr());
                    AppendMenuW(hmenu, MF_STRING, 2, m_toggle.as_ptr());
                    AppendMenuW(hmenu, MF_STRING, 3, m_exit.as_ptr());
                    let cmd = TrackPopupMenu(hmenu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, std::ptr::null());
                    DestroyMenu(hmenu);
                    if cmd == 1 {
                        let _ = proxy_ref.send_event(UserEvent::TrayShow);
                    } else if cmd == 2 {
                        let _ = proxy_ref.send_event(UserEvent::TrayToggleRelay);
                    } else if cmd == 3 {
                        let _ = proxy_ref.send_event(UserEvent::TrayExit);
                    }
                }
                return 0;
            }

            DefSubclassProc(hwnd, msg, wparam, lparam)
        }

        let proxy_ptr = Box::into_raw(Box::new(proxy.clone()));
        SetWindowSubclass(hwnd, power_subclass_proc, 2026, proxy_ptr as usize);
    }

    let builder = WebViewBuilder::new()
        .with_background_color((9, 13, 20, 255))
        .with_html(include_str!("ui.html"))
        .with_ipc_handler(move |req| {
            let _ = proxy_ipc.send_event(UserEvent::Ipc(req.body().clone()));
        })
        .with_drag_drop_handler(move |event| {
            if let DragDropEvent::Drop { paths, .. } = event {
                if let Some(first) = paths.into_iter().next() {
                    let _ = proxy_drop.send_event(UserEvent::Dropped(first));
                }
            }
            true
        });

    let webview = match builder.build(&window) {
        Ok(w) => w,
        Err(e) => {
            let err_msg = format!("ShadowProxy 界面引擎 (WebView2) 启动失败:\n{}\n\n请确认系统已安装 Microsoft Edge WebView2 Runtime。", e);
            show_win32_error_box("ShadowProxy 启动失败", &err_msg);
            anyhow::bail!("{}", err_msg);
        }
    };
    log_step("5. WebViewBuilder built successfully");

    let mut state = AppState::new()?;
    log_step("6. AppState created, starting tick thread and event loop");

    // 250ms 保底唤醒显示窗口（防止极端异常下未能触发 window_ready 导致窗口不可见）
    {
        let proxy_show = proxy.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let _ = proxy_show.send_event(UserEvent::Ipc(r#"{"cmd":"window_ready"}"#.to_string()));
        });
    }

    // 1 秒定时发送 Tick 维持流量与状态轮询，并内置时钟跳跃休眠唤醒双保险感知
    {
        let proxy_tick = proxy.clone();
        std::thread::spawn(move || {
            let mut last_tick = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                let elapsed = last_tick.elapsed();
                last_tick = std::time::Instant::now();

                // 若原本休眠 1000ms 的线程实际历时超过 3000ms，说明系统经历了睡眠/休眠/挂起恢复
                if elapsed > std::time::Duration::from_millis(3000) {
                    let _ = proxy_tick.send_event(UserEvent::SystemResume);
                }

                if proxy_tick.send_event(UserEvent::Tick).is_err() {
                    break;
                }
            }
        });
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(user_event) => match user_event {
                UserEvent::SystemSuspend => {
                    state.last_log = Some("[SYS] 系统准备进入休眠/睡眠模式...".to_string());
                }
                UserEvent::SystemResume => {
                    state.handle_system_resume();
                    let full = state.get_full_state();
                    if let Ok(json) = serde_json::to_string(&full) {
                        let _ = webview.evaluate_script(&format!(
                            "window.updateState({});",
                            json
                        ));
                    }
                }
                UserEvent::Log(msg) => {
                    state.last_log = Some(msg);
                    let full = state.get_full_state();
                    if let Ok(json) = serde_json::to_string(&full) {
                        let _ = webview.evaluate_script(&format!(
                            "window.updateState({});",
                            json
                        ));
                    }
                }
                UserEvent::Tick => {
                    state.update_process_statuses();
                    let full = state.get_full_state();
                    if let Ok(json) = serde_json::to_string(&full) {
                        let _ = webview.evaluate_script(&format!(
                            "window.updateState({});",
                            json
                        ));
                    }
                }
                UserEvent::Dropped(path) => {
                    let (display_path, args) = if let Some((real_exe, lnk_args)) = shadow_injector::resolve_shortcut(&path) {
                        (real_exe.to_string_lossy().to_string(), lnk_args)
                    } else {
                        (path.to_string_lossy().to_string(), None)
                    };
                    if let Ok(json_path) = serde_json::to_string(&display_path) {
                        let json_args = serde_json::to_string(&args.unwrap_or_default()).unwrap_or_default();
                        let _ = webview.evaluate_script(&format!(
                            "window.updateDroppedFile({}, {});",
                            json_path,
                            json_args
                        ));
                    }
                }
                UserEvent::Ipc(raw_json) => {
                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(&raw_json) {
                        match cmd {
                            IpcCommand::GetState => {
                                state.update_process_statuses();
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::StartRelay { proxy, strict_dns } => {
                                if let Err(e) = state.start_relay(&proxy, strict_dns) {
                                    state.last_log = Some(format!("[ERR] {}", e));
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::StopRelay => {
                                state.stop_relay();
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::SetProxyConfig { proxy, strict_dns } => {
                                let clean = proxy.trim().to_string();
                                if clean.parse::<SocketAddr>().is_ok() {
                                    state.upstream_proxy = clean.clone();
                                    state.strict_dns = strict_dns;
                                    state.save_config();
                                    if state.relay.is_some() {
                                        if let Err(e) = state.start_relay(&state.upstream_proxy.clone(), strict_dns) {
                                            state.last_log = Some(format!("[RELAY] 重启中继失败: {}", e));
                                        }
                                    }
                                } else {
                                    state.last_log = Some(format!("[CONFIG] 忽略无效上游代理格式: {}", clean));
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::LaunchProcess { target, args, proxy, strict_dns } => {
                                if let Some(p) = proxy {
                                    let clean = p.trim().to_string();
                                    if !clean.is_empty() && clean != state.upstream_proxy && clean.parse::<SocketAddr>().is_ok() {
                                        state.upstream_proxy = clean.clone();
                                        if state.relay.is_some() {
                                            let dns = strict_dns.unwrap_or(state.strict_dns);
                                            if let Err(e) = state.start_relay(&clean, dns) {
                                                state.last_log = Some(format!("[RELAY] 重启中继失败: {}", e));
                                            }
                                        }
                                    }
                                }
                                if let Some(dns) = strict_dns {
                                    state.strict_dns = dns;
                                }
                                if let Err(e) =
                                    state.launch_process(&target, args.as_deref())
                                {
                                    state.last_log = Some(format!("[ERR] {}", e));
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::BrowseFile => {
                                if let Some(picked) = pick_executable_file(hwnd) {
                                    let (display_path, args) = if let Some((real_exe, lnk_args)) = shadow_injector::resolve_shortcut(&picked) {
                                        (real_exe.to_string_lossy().to_string(), lnk_args)
                                    } else {
                                        (picked.to_string_lossy().to_string(), None)
                                    };
                                    if let Ok(json_path) = serde_json::to_string(&display_path) {
                                        let json_args = serde_json::to_string(&args.unwrap_or_default()).unwrap_or_default();
                                        let _ = webview.evaluate_script(&format!(
                                            "window.updateDroppedFile({}, {});",
                                            json_path,
                                            json_args
                                        ));
                                    }
                                }
                            }
                            IpcCommand::KillProcess { pid } => {
                                state.kill_process(pid);
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::AddPreset { name, target, args } => {
                                let clean_target = target.trim().to_string();
                                if !clean_target.is_empty() {
                                    let clean_args = args.unwrap_or_default().trim().to_string();
                                    let display_name = name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| {
                                        Path::new(&clean_target)
                                            .file_name()
                                            .map(|f| f.to_string_lossy().to_string())
                                            .unwrap_or_else(|| clean_target.clone())
                                    });

                                    state.presets.retain(|p| {
                                        !(p.target.eq_ignore_ascii_case(&clean_target) && p.args == clean_args)
                                    });

                                    let icon = icon_extractor::extract_icon_as_base64_png(&clean_target);

                                    state.presets.insert(0, PresetItem {
                                        name: display_name.clone(),
                                        target: clean_target,
                                        args: clean_args,
                                        icon,
                                    });

                                    if state.presets.len() > 32 {
                                        state.presets.truncate(32);
                                    }
                                    state.save_presets();
                                    state.last_log = Some(format!("[PRESET] 已添加快捷预设: {}", display_name));
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::DeletePreset { index } => {
                                if index < state.presets.len() {
                                    let removed = state.presets.remove(index);
                                    state.save_presets();
                                    state.last_log = Some(format!("[PRESET] 已删除快捷预设: {}", removed.name));
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::AddRule { name, pattern_type, pattern_val, action } => {
                                let act = match action.to_lowercase().as_str() {
                                    "direct" => RouteAction::Direct,
                                    "block" => RouteAction::Block,
                                    _ => RouteAction::Proxy,
                                };
                                let pat = match pattern_type.to_lowercase().as_str() {
                                    "domain_suffix" => RulePattern::DomainSuffix(pattern_val.trim_start_matches('.').to_string()),
                                    "domain_keyword" => RulePattern::DomainKeyword(pattern_val),
                                    "domain_exact" => RulePattern::DomainExact(pattern_val),
                                    "ip_cidr" => {
                                        let parts: Vec<&str> = pattern_val.split('/').collect();
                                        let ip = parts[0].trim().to_string();
                                        let prefix_len = parts.get(1).and_then(|p| p.trim().parse::<u8>().ok()).unwrap_or(32);
                                        RulePattern::IpCidr { ip, prefix_len }
                                    }
                                    "port" => {
                                        let p = pattern_val.trim().parse::<u16>().unwrap_or(80);
                                        RulePattern::Port(p)
                                    }
                                    "port_range" => {
                                        let clean = pattern_val.replace("..", "-");
                                        let parts: Vec<&str> = clean.split('-').collect();
                                        let start = parts[0].trim().parse::<u16>().unwrap_or(1);
                                        let end = parts.get(1).and_then(|p| p.trim().parse::<u16>().ok()).unwrap_or(start);
                                        RulePattern::PortRange { start, end }
                                    }
                                    "process_name" | "process" => RulePattern::ProcessName(pattern_val),
                                    _ => RulePattern::Final,
                                };
                                let rule_id = format!("rule-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                                {
                                    let mut router = state.router.write().unwrap();
                                    router.add_rule(RuleItem {
                                        id: rule_id,
                                        name: name.clone(),
                                        pattern: pat,
                                        action: act,
                                        enabled: true,
                                    });
                                }
                                state.save_rules();
                                state.last_log = Some(format!("[RULE] 已新增分流规则: {}", name));
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::MoveRule { from, to } => {
                                {
                                    let mut router = state.router.write().unwrap();
                                    router.move_rule(from, to);
                                }
                                state.save_rules();
                                state.last_log = Some("[RULE] 规则优先级已调整".to_string());
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::ImportRules { json } => {
                                let mut imported_count = 0;
                                if let Ok(new_router) = Router::from_json(&json) {
                                    let mut router = state.router.write().unwrap();
                                    for r in new_router.rules {
                                        if !matches!(r.pattern, RulePattern::Final) {
                                            router.add_rule(r);
                                            imported_count += 1;
                                        }
                                    }
                                } else if let Ok(new_rules) = serde_json::from_str::<Vec<RuleItem>>(&json) {
                                    let mut router = state.router.write().unwrap();
                                    for r in new_rules {
                                        if !matches!(r.pattern, RulePattern::Final) {
                                            router.add_rule(r);
                                            imported_count += 1;
                                        }
                                    }
                                }
                                state.save_rules();
                                state.last_log = Some(format!("[RULE] 成功导入 {} 条规则", imported_count));
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::ClearRules => {
                                {
                                    let mut router = state.router.write().unwrap();
                                    router.clear_custom_rules();
                                }
                                state.save_rules();
                                state.last_log = Some("[RULE] 已清空自定义分流规则".to_string());
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::AttachProcess { pid } => {
                                match state.attach_process(pid) {
                                    Ok(()) => {}
                                    Err(e) => {
                                        state.last_log = Some(format!("[INJECT] 附加注入失败: {}", e));
                                    }
                                }
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::ListSystemProcesses => {
                                let procs = list_system_processes();
                                if let Ok(json) = serde_json::to_string(&procs) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.onSystemProcessesLoaded({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::UpdatePreset { index, name, target, args } => {
                                state.update_preset(index, name, target, args);
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::DeleteRule { id } => {
                                {
                                    let mut router = state.router.write().unwrap();
                                    router.remove_rule(&id);
                                }
                                state.save_rules();
                                state.last_log = Some("[RULE] 已删除分流规则".to_string());
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::ToggleRule { id, enabled } => {
                                {
                                    let mut router = state.router.write().unwrap();
                                    router.set_rule_enabled(&id, enabled);
                                }
                                state.save_rules();
                                state.last_log = Some(format!("[RULE] 规则状态已更新 (启用={})", enabled));
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::SetRulePreset { preset } => {
                                let new_router = match preset.to_lowercase().as_str() {
                                    "smart" => Router::preset_smart(),
                                    "global" | "global_proxy" => Router::preset_global_proxy(),
                                    "direct" | "direct_all" => Router::preset_direct_all(),
                                    _ => Router::preset_smart(),
                                };
                                {
                                    let mut router = state.router.write().unwrap();
                                    *router = new_router;
                                }
                                state.save_rules();
                                state.last_log = Some(format!("[RULE] 已切换分流预设为: {}", preset));
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::ClearSessions => {
                                state.tracker.clear();
                                state.last_log = Some("[SESSION] 实时连接历史已清空".to_string());
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::PingUpstream { proxy } => {
                                state.ping_upstream(&proxy);
                                let full = state.get_full_state();
                                if let Ok(json) = serde_json::to_string(&full) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.updateState({});",
                                        json
                                    ));
                                }
                            }
                            IpcCommand::WindowReady => {
                                window.set_visible(true);
                            }
                            IpcCommand::OpenUrl { url } => {
                                let clean = url.trim().to_string();
                                if clean.starts_with("https://") || clean.starts_with("http://") {
                                    use windows_sys::Win32::UI::Shell::ShellExecuteW;
                                    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
                                    let url_w: Vec<u16> = clean.encode_utf16().chain(std::iter::once(0)).collect();
                                    let open_w: Vec<u16> = "open\0".encode_utf16().collect();
                                    unsafe {
                                        ShellExecuteW(
                                            0 as _,
                                            open_w.as_ptr(),
                                            url_w.as_ptr(),
                                            core::ptr::null(),
                                            core::ptr::null(),
                                            SW_SHOWNORMAL,
                                        );
                                    }
                                }
                            }
                            IpcCommand::DownloadAndInstall { url, filename } => {
                                if IS_DOWNLOADING
                                    .compare_exchange(
                                        false,
                                        true,
                                        std::sync::atomic::Ordering::SeqCst,
                                        std::sync::atomic::Ordering::SeqCst,
                                    )
                                    .is_err()
                                {
                                    let _ = proxy.send_event(UserEvent::Log(
                                        "[UPDATE] 安装包正在下载中，请勿重复操作".to_string(),
                                    ));
                                } else {
                                    let clean_url = url.trim().to_string();
                                    if !clean_url.starts_with("https://github.com/")
                                        && !clean_url.starts_with("https://objects.githubusercontent.com/")
                                    {
                                        IS_DOWNLOADING.store(false, std::sync::atomic::Ordering::SeqCst);
                                        let _ = proxy.send_event(UserEvent::Log(
                                            "[UPDATE] 下载链接非官方 GitHub 仓库，已拒绝下载".to_string(),
                                        ));
                                    } else {
                                        let proxy_ev = proxy.clone();
                                        let upstream = state.upstream_proxy.clone();
                                        std::thread::spawn(move || {
                                            struct DownloadGuard;
                                            impl Drop for DownloadGuard {
                                                fn drop(&mut self) {
                                                    IS_DOWNLOADING.store(false, std::sync::atomic::Ordering::SeqCst);
                                                }
                                            }
                                            let _guard = DownloadGuard;

                                            use std::os::windows::process::CommandExt;
                                            let temp_dir = std::env::temp_dir();
                                            let safe_name = std::path::Path::new(&filename)
                                                .file_name()
                                                .and_then(|s| s.to_str())
                                                .map(|s| s.trim())
                                                .filter(|s| {
                                                    s.ends_with(".exe")
                                                        && !s.is_empty()
                                                        && !s.contains("..")
                                                        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
                                                })
                                                .unwrap_or("ShadowProxy-Setup.exe");
                                            let dest = temp_dir.join(safe_name);

                                            let _ = proxy_ev.send_event(UserEvent::Log(format!("[UPDATE] 正在下载最新安装包: {}", safe_name)));

                                            let proxy_arg = format_curl_proxy(&upstream);
                                            let run_download = |p: Option<&str>| -> Result<(), i32> {
                                                let mut cmd = std::process::Command::new("curl.exe");
                                                cmd.args([
                                                    "-L",
                                                    "--fail",
                                                    "--silent",
                                                    "--show-error",
                                                    "--connect-timeout",
                                                    "15",
                                                    "--max-time",
                                                    "600",
                                                    "-o",
                                                    dest.to_string_lossy().as_ref(),
                                                ]);
                                                if let Some(proxy_val) = p {
                                                    cmd.arg("--proxy").arg(proxy_val);
                                                }
                                                cmd.arg("--").arg(&clean_url);
                                                cmd.creation_flags(0x08000000);
                                                match cmd.status() {
                                                    Ok(s) if s.success() && dest.exists() => Ok(()),
                                                    Ok(s) => Err(s.code().unwrap_or(-1)),
                                                    Err(_) => Err(-2),
                                                }
                                            };

                                            let mut res = if let Some(ref p) = proxy_arg {
                                                run_download(Some(p))
                                            } else {
                                                run_download(None)
                                            };

                                            if res.is_err() && proxy_arg.is_some() {
                                                if let Some(ref p) = proxy_arg {
                                                    if p.starts_with("socks5h://") {
                                                        let http_proxy = format!("http://{}", p.trim_start_matches("socks5h://"));
                                                        res = run_download(Some(&http_proxy));
                                                    }
                                                }
                                                if res.is_err() {
                                                    res = run_download(None);
                                                }
                                            }

                                            match res {
                                                Ok(()) => {
                                                    let _ = proxy_ev.send_event(UserEvent::Log("[UPDATE] 安装包下载完成，正在启动安装程序...".to_string()));
                                                    let _ = proxy_ev.send_event(UserEvent::Log("[UPDATE] 安装程序已启动，请退出当前程序以完成更新".to_string()));
                                                    use std::os::windows::ffi::OsStrExt;
                                                    let exe_w: Vec<u16> = dest.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
                                                    let open_w: Vec<u16> = "open\0".encode_utf16().collect();
                                                    unsafe {
                                                        windows_sys::Win32::UI::Shell::ShellExecuteW(
                                                            0 as _,
                                                            open_w.as_ptr(),
                                                            exe_w.as_ptr(),
                                                            core::ptr::null(),
                                                            core::ptr::null(),
                                                            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
                                                        );
                                                    }
                                                    let _ = proxy_ev.send_event(UserEvent::Log("[UPDATE] 安装向导已就绪，当前程序将在 1 秒后自动安全退出...".to_string()));
                                                    std::thread::sleep(std::time::Duration::from_millis(1000));
                                                    let _ = proxy_ev.send_event(UserEvent::TrayExit);
                                                }
                                                Err(code) => {
                                                    let _ = proxy_ev.send_event(UserEvent::Log(format!("[UPDATE] 下载安装包失败 (代码: {:?})，建议前往 GitHub 手动下载", code)));
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                            IpcCommand::CheckUpdate { silent } => {
                                let proxy_ev = proxy.clone();
                                let upstream = state.upstream_proxy.clone();
                                std::thread::spawn(move || {
                                    match check_github_update(&upstream) {
                                        Ok(data) => {
                                            let _ = proxy_ev.send_event(UserEvent::UpdateCheckResult {
                                                silent,
                                                success: true,
                                                error: None,
                                                data: Some(data),
                                            });
                                        }
                                        Err(err) => {
                                            let _ = proxy_ev.send_event(UserEvent::UpdateCheckResult {
                                                silent,
                                                success: false,
                                                error: Some(err),
                                                data: None,
                                            });
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
                UserEvent::TrayShow => {
                    window.set_visible(true);
                    window.set_focus();
                }
                UserEvent::TrayToggleRelay => {
                    if state.relay.is_some() {
                        state.stop_relay();
                        state.last_log = Some("[RELAY] 已通过托盘菜单停止中继服务".to_string());
                    } else {
                        let p = state.upstream_proxy.clone();
                        let d = state.strict_dns;
                        if let Err(e) = state.start_relay(&p, d) {
                            state.last_log = Some(format!("[RELAY] 托盘启动中继失败: {}", e));
                        } else {
                            state.last_log = Some("[RELAY] 已通过托盘菜单启动中继服务".to_string());
                        }
                    }
                    let full = state.get_full_state();
                    if let Ok(json) = serde_json::to_string(&full) {
                        let _ = webview.evaluate_script(&format!(
                            "window.updateState({});",
                            json
                        ));
                    }
                }
                UserEvent::UpdateCheckResult {
                    silent,
                    success,
                    error,
                    data,
                } => {
                    let res_obj = serde_json::json!({
                        "silent": silent,
                        "success": success,
                        "error": error,
                        "data": data,
                    });
                    if let Ok(json) = serde_json::to_string(&res_obj) {
                        let _ = webview.evaluate_script(&format!(
                            "if (window.onUpdateCheckResult) {{ window.onUpdateCheckResult({}); }}",
                            json
                        ));
                    }
                }
                UserEvent::TrayExit => {
                    if !nid.hWnd.is_null() {
                        unsafe {
                            windows_sys::Win32::UI::Shell::Shell_NotifyIconW(
                                windows_sys::Win32::UI::Shell::NIM_DELETE,
                                &nid,
                            );
                        }
                    }
                    state.stop_relay();
                    for p in &mut state.processes {
                        if !p.handle.is_null() {
                            unsafe {
                                windows_sys::Win32::Foundation::CloseHandle(p.handle);
                            }
                            p.handle = core::ptr::null_mut();
                        }
                    }
                    *control_flow = ControlFlow::Exit;
                    std::process::exit(0);
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
                state.last_log = Some("[SYS] 窗口已最小化至系统托盘常驻运行".to_string());
                let full = state.get_full_state();
                if let Ok(json) = serde_json::to_string(&full) {
                    let _ = webview.evaluate_script(&format!(
                        "window.updateState({});",
                        json
                    ));
                }
            }
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ui_command_deserialization() {
        // 1. window_ready
        let cmd: IpcCommand = serde_json::from_str(r#"{"cmd":"window_ready"}"#).unwrap();
        assert!(matches!(cmd, IpcCommand::WindowReady));

        // 2. add_rule
        let cmd: IpcCommand = serde_json::from_str(
            r#"{"cmd":"add_rule","name":"测试规则","pattern_type":"Domain","pattern_val":"example.com","action":"Proxy"}"#,
        )
        .unwrap();
        if let IpcCommand::AddRule {
            name,
            pattern_type,
            pattern_val,
            action,
        } = cmd
        {
            assert_eq!(name, "测试规则");
            assert_eq!(pattern_type, "Domain");
            assert_eq!(pattern_val, "example.com");
            assert_eq!(action, "Proxy");
        } else {
            panic!("反序列化类型不匹配");
        }

        // 3. kill_process
        let cmd: IpcCommand = serde_json::from_str(r#"{"cmd":"kill_process","pid":12345}"#).unwrap();
        if let IpcCommand::KillProcess { pid } = cmd {
            assert_eq!(pid, 12345);
        } else {
            panic!("反序列化类型不匹配");
        }

        // 4. set_rule_preset
        let cmd: IpcCommand =
            serde_json::from_str(r#"{"cmd":"set_rule_preset","preset":"smart"}"#).unwrap();
        if let IpcCommand::SetRulePreset { preset } = cmd {
            assert_eq!(preset, "smart");
        } else {
            panic!("反序列化类型不匹配");
        }

        // 5. set_proxy_config
        let cmd: IpcCommand = serde_json::from_str(
            r#"{"cmd":"set_proxy_config","proxy":"127.0.0.1:7890","strict_dns":false}"#,
        )
        .unwrap();
        if let IpcCommand::SetProxyConfig { proxy, strict_dns } = cmd {
            assert_eq!(proxy, "127.0.0.1:7890");
            assert!(!strict_dns);
        } else {
            panic!("反序列化类型不匹配");
        }

        // 6. attach_process
        let cmd: IpcCommand = serde_json::from_str(r#"{"cmd":"attach_process","pid":9876}"#).unwrap();
        if let IpcCommand::AttachProcess { pid } = cmd {
            assert_eq!(pid, 9876);
        } else {
            panic!("反序列化类型不匹配");
        }

        // 7. move_rule
        let cmd: IpcCommand = serde_json::from_str(r#"{"cmd":"move_rule","from":1,"to":0}"#).unwrap();
        if let IpcCommand::MoveRule { from, to } = cmd {
            assert_eq!(from, 1);
            assert_eq!(to, 0);
        } else {
            panic!("反序列化类型不匹配");
        }

        // 8. update_preset
        let cmd: IpcCommand = serde_json::from_str(
            r#"{"cmd":"update_preset","index":0,"name":"Git 终端","target":"git.exe","args":"status"}"#,
        )
        .unwrap();
        if let IpcCommand::UpdatePreset { index, name, target, args } = cmd {
            assert_eq!(index, 0);
            assert_eq!(name, "Git 终端");
            assert_eq!(target, "git.exe");
            assert_eq!(args, "status");
        } else {
            panic!("反序列化类型不匹配");
        }
    }

    #[test]
    fn test_invalid_proxy_addr_parse_rejection() {
        assert!("127.0.0.1".parse::<SocketAddr>().is_err());
        assert!("invalid-proxy".parse::<SocketAddr>().is_err());
        assert!("127.0.0.1:7897".parse::<SocketAddr>().is_ok());
    }

    #[test]
    fn test_app_config_serialization() {
        let cfg = AppConfig {
            upstream_proxy: "127.0.0.1:10808".to_string(),
            strict_dns: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let loaded: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.upstream_proxy, "127.0.0.1:10808");
        assert!(loaded.strict_dns);
    }
}
