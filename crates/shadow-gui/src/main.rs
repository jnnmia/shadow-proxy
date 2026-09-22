//! shadow-gui: ShadowProxy 图形桌面交互端
//!
//! 基于 Wry / Tao 原生 WebView 构建的高性能极简控制台，
//! 负责本地透明中继管理、双架构目标程序注入、拖拽捕获与实时流量看板。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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

#[derive(Debug)]
enum UserEvent {
    Ipc(String),
    Dropped(PathBuf),
    Tick,
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
    #[serde(rename = "kill_process")]
    KillProcess { pid: u32 },
    #[serde(rename = "add_preset")]
    AddPreset {
        name: Option<String>,
        target: String,
        args: Option<String>,
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
    #[serde(rename = "window_ready")]
    WindowReady,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PresetItem {
    pub name: String,
    pub target: String,
    pub args: String,
}

#[derive(Serialize, Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    name: String,
    path: String,
    arch: String,
    running: bool,
    exit_code: u32,
}

struct TrackedProcess {
    pid: u32,
    name: String,
    path: String,
    arch: String,
    handle: windows_sys::Win32::Foundation::HANDLE,
    running: bool,
    exit_code: u32,
}

#[derive(Serialize, Debug)]
struct FullState {
    relay_active: bool,
    relay_addr: Option<String>,
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

struct AppState {
    rt: tokio::runtime::Runtime,
    relay: Option<ActiveRelay>,
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
                    if let Ok(items) = serde_json::from_str::<Vec<PresetItem>>(&content) {
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
                defaults.push(PresetItem {
                    name: "Antigravity (AI IDE)".to_string(),
                    target: ag_path.to_string_lossy().to_string(),
                    args: "--no-proxy-server".to_string(),
                });
            }
        }
        defaults.push(PresetItem {
            name: "curl.exe (连通性测速)".to_string(),
            target: "C:\\Windows\\System32\\curl.exe".to_string(),
            args: "https://api.ipify.org -v".to_string(),
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

    fn new() -> anyhow::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let presets = Self::load_presets();
        let router = Arc::new(RwLock::new(Self::load_rules()));
        let tracker = Arc::new(SessionTracker::new(200));

        Ok(Self {
            rt,
            relay: None,
            upstream_proxy: "127.0.0.1:7897".to_string(),
            strict_dns: true,
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
        self.stop_relay();

        let upstream_proxy: SocketAddr = proxy_str
            .parse()
            .map_err(|e| format!("上游代理地址无效: {}", e))?;

        let listen_addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| format!("监听地址解析失败: {}", e))?;

        let config = RelayConfig {
            listen_addr,
            upstream_proxy,
            proxy_auth: None,
            strict_dns,
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

        self.relay = Some(ActiveRelay {
            shutdown_tx,
            _stats: stats,
            local_addr,
        });
        self.upstream_proxy = proxy_str.to_string();
        self.strict_dns = strict_dns;
        self.last_log = Some(format!(
            "[RELAY] 本地透明中继已启动在 {}, 上游: {}",
            local_addr, upstream_proxy
        ));

        Ok(local_addr)
    }

    fn stop_relay(&mut self) {
        if let Some(active) = self.relay.take() {
            let _ = active.shutdown_tx.send(());
            self.last_log = Some("[RELAY] 本地透明中继已停止".to_string());
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

        self.processes.push(TrackedProcess {
            pid,
            name: file_name,
            path: target_str.to_string(),
            arch: format!("{:?}", arch),
            handle,
            running: true,
            exit_code: 0,
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

            for (child_pid, _parent_pid, child_name) in children {
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

                    self.processes.push(TrackedProcess {
                        pid: child_pid,
                        name: child_name.clone(),
                        path: child_name.clone(),
                        arch: "X64".to_string(),
                        handle,
                        running: true,
                        exit_code: 0,
                    });

                    self.last_log = Some(format!(
                        "[INJECT] 自动纳管并注入子进程 {} (PID: {})",
                        child_name, child_pid
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
                name: p.name.clone(),
                path: p.path.clone(),
                arch: p.arch.clone(),
                running: p.running,
                exit_code: p.exit_code,
            })
            .collect();

        let rules = self.router.read().unwrap().rules.clone();
        let sessions = self.tracker.list_sessions(60);

        FullState {
            relay_active: self.relay.is_some(),
            relay_addr: self.relay.as_ref().map(|r| r.local_addr.to_string()),
            bytes_sent,
            bytes_received,
            speed_up_bps,
            speed_down_bps,
            processes: procs,
            presets: self.presets.clone(),
            rules,
            sessions,
            last_log: self.last_log.clone(),
            ping_ms: self.ping_ms,
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

    // 设置窗口标题栏与任务栏大/小专属图标
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
        }
    }

    let proxy = event_loop.create_proxy();
    let proxy_ipc = proxy.clone();
    let proxy_drop = proxy.clone();

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

    // 1 秒定时发送 Tick 维持流量与状态轮询（在确认 WebView2 与状态初始化成功后启动）
    {
        let proxy_tick = proxy.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            if proxy_tick.send_event(UserEvent::Tick).is_err() {
                break;
            }
        });
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(user_event) => match user_event {
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
                            IpcCommand::LaunchProcess { target, args, proxy, strict_dns } => {
                                if let Some(p) = proxy {
                                    let clean = p.trim().to_string();
                                    if !clean.is_empty() && clean != state.upstream_proxy {
                                        state.upstream_proxy = clean.clone();
                                        if state.relay.is_some() {
                                            let dns = strict_dns.unwrap_or(state.strict_dns);
                                            let _ = state.start_relay(&clean, dns);
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

                                    state.presets.insert(0, PresetItem {
                                        name: display_name.clone(),
                                        target: clean_target,
                                        args: clean_args,
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
                        }
                    }
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
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
            _ => {}
        }
    });
}
