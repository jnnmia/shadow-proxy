//! ghost-hook: 注入目标进程空间的微运行时 Winsock API Hook 动态库

#![allow(clippy::missing_safety_doc, clippy::manual_c_str_literals)]

pub mod fakeip;
pub mod iat;
pub mod protocol;
pub mod winsock_hook;

use std::ffi::c_void;
use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;

pub fn hook_log(msg: &str) {
    if std::env::var_os("SHADOW_DEBUG").is_none() {
        return;
    }
    // 规避 Loader Lock 死锁：采用 Win32 原生 OutputDebugStringA 输出调试信息，杜绝文件系统 I/O 与死锁
    let formatted = format!("[shadow-hook][PID {}] {}\0", std::process::id(), msg);
    unsafe {
        OutputDebugStringA(formatted.as_ptr());
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            DisableThreadLibraryCalls(hinst);
            iat::OUR_MODULE_BASE.store(hinst as usize, Ordering::Relaxed);
            hook_log("DLL_PROCESS_ATTACH entered");
            init_hooks();
        }
        DLL_PROCESS_DETACH => {
            restore_hooks();
        }
        _ => {}
    }
    TRUE
}

pub fn parse_relay_state_str(content: &str) -> Option<(u16, bool)> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split(',');
    let port_str = parts.next()?.trim();
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    let strict_dns = match parts.next().map(|s| s.trim()) {
        Some("0") | Some("false") | Some("FALSE") => false,
        _ => true,
    };
    Some((port, strict_dns))
}

fn read_shared_relay_state() -> Option<(u16, bool)> {
    let local_appdata = std::env::var("LOCALAPPDATA").ok()?;
    let path = std::path::Path::new(&local_appdata)
        .join("ShadowProxy")
        .join("relay.state");
    let content = std::fs::read_to_string(path).ok()?;
    parse_relay_state_str(&content)
}

fn init_env_config() {
    let port_res = std::env::var("SHADOW_RELAY_PORT").or_else(|_| std::env::var("GHOST_RELAY_PORT"));
    let mut has_env_port = false;
    if let Ok(port_str) = port_res {
        if let Ok(port) = port_str.parse::<u16>() {
            winsock_hook::RELAY_PORT.store(port, Ordering::Relaxed);
            has_env_port = true;
        }
    }

    let strict_res = std::env::var("SHADOW_STRICT_DNS").or_else(|_| std::env::var("GHOST_STRICT_DNS"));
    if let Ok(strict_str) = strict_res {
        let strict = !(strict_str == "0" || strict_str.eq_ignore_ascii_case("false"));
        winsock_hook::STRICT_DNS.store(strict, Ordering::Relaxed);
    }

    // 运行时动态附加 (Runtime Attach) 的进程未继承主控环境变量，回退读取共享状态文件并注入当前环境以供后续子进程继承
    if !has_env_port {
        if let Some((port, strict_dns)) = read_shared_relay_state() {
            winsock_hook::RELAY_PORT.store(port, Ordering::Relaxed);
            winsock_hook::STRICT_DNS.store(strict_dns, Ordering::Relaxed);
            let port_str = port.to_string();
            let dns_str = if strict_dns { "1" } else { "0" };
            std::env::set_var("SHADOW_RELAY_PORT", &port_str);
            std::env::set_var("GHOST_RELAY_PORT", &port_str);
            std::env::set_var("SHADOW_STRICT_DNS", dns_str);
            std::env::set_var("GHOST_STRICT_DNS", dns_str);
        }
    }
}

unsafe fn sanitize_environment() {
    let proxy_vars: [&[u16]; 8] = [
        &[b'H' as u16, b'T' as u16, b'T' as u16, b'P' as u16, b'_' as u16, b'P' as u16, b'R' as u16, b'O' as u16, b'X' as u16, b'Y' as u16, 0],
        &[b'H' as u16, b'T' as u16, b'T' as u16, b'P' as u16, b'S' as u16, b'_' as u16, b'P' as u16, b'R' as u16, b'O' as u16, b'X' as u16, b'Y' as u16, 0],
        &[b'A' as u16, b'L' as u16, b'L' as u16, b'_' as u16, b'P' as u16, b'R' as u16, b'O' as u16, b'X' as u16, b'Y' as u16, 0],
        &[b'N' as u16, b'O' as u16, b'_' as u16, b'P' as u16, b'R' as u16, b'O' as u16, b'X' as u16, b'Y' as u16, 0],
        &[b'h' as u16, b't' as u16, b't' as u16, b'p' as u16, b'_' as u16, b'p' as u16, b'r' as u16, b'o' as u16, b'x' as u16, b'y' as u16, 0],
        &[b'h' as u16, b't' as u16, b't' as u16, b'p' as u16, b's' as u16, b'_' as u16, b'p' as u16, b'r' as u16, b'o' as u16, b'x' as u16, b'y' as u16, 0],
        &[b'a' as u16, b'l' as u16, b'l' as u16, b'_' as u16, b'p' as u16, b'r' as u16, b'o' as u16, b'x' as u16, b'y' as u16, 0],
        &[b'n' as u16, b'o' as u16, b'_' as u16, b'p' as u16, b'r' as u16, b'o' as u16, b'x' as u16, b'y' as u16, 0],
    ];
    let k32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if !k32.is_null() {
        if let Some(p) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(k32, b"SetEnvironmentVariableW\0".as_ptr()) {
            let set_env: unsafe extern "system" fn(*const u16, *const u16) -> BOOL = std::mem::transmute(p);
            for var in proxy_vars {
                set_env(var.as_ptr(), std::ptr::null());
            }
        }
    }
}

fn init_hooks() {
    init_env_config();

    // 2. 初始化真实 Winsock 函数指针并对所有模块打桩
    unsafe {
        sanitize_environment();
        winsock_hook::init_original_pointers();
        winsock_hook::reapply_hooks();
    }
}

fn restore_hooks() {
    // 进程退出时系统自动回收虚拟内存，微运行时保持简洁无冗余销毁逻辑
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_port_env() {
        std::env::set_var("SHADOW_RELAY_PORT", "19090");
        init_env_config();
        assert_eq!(winsock_hook::RELAY_PORT.load(Ordering::Relaxed), 19090);
    }

    #[test]
    fn test_strict_dns_env() {
        std::env::set_var("SHADOW_STRICT_DNS", "false");
        init_env_config();
        assert!(!winsock_hook::STRICT_DNS.load(Ordering::Relaxed));
    }

    #[test]
    fn test_parse_relay_state_str() {
        assert_eq!(parse_relay_state_str("19090,1"), Some((19090, true)));
        assert_eq!(parse_relay_state_str("54321,0\n"), Some((54321, false)));
        assert_eq!(parse_relay_state_str("0,1"), None);
        assert_eq!(parse_relay_state_str("invalid"), None);
    }
}

