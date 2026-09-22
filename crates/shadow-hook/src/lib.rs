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

pub fn hook_log(msg: &str) {
    if std::env::var_os("SHADOW_DEBUG").is_none() {
        return;
    }
    use std::io::Write;
    let exe = std::env::current_exe()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
        .unwrap_or_default();
    let log_path = std::env::temp_dir().join("shadow_hook.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(f, "[PID {} ({})] {}", std::process::id(), exe, msg);
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

fn init_env_config() {
    let port_res = std::env::var("SHADOW_RELAY_PORT").or_else(|_| std::env::var("GHOST_RELAY_PORT"));
    if let Ok(port_str) = port_res {
        if let Ok(port) = port_str.parse::<u16>() {
            winsock_hook::RELAY_PORT.store(port, Ordering::Relaxed);
        }
    }

    let strict_res = std::env::var("SHADOW_STRICT_DNS").or_else(|_| std::env::var("GHOST_STRICT_DNS"));
    if let Ok(strict_str) = strict_res {
        if strict_str == "0" || strict_str.eq_ignore_ascii_case("false") {
            winsock_hook::STRICT_DNS.store(false, Ordering::Relaxed);
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
}

