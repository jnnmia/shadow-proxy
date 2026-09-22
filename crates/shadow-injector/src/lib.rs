//! ghost-injector: 进程启动挂起、双架构 PE 判定与 DLL 注入器

#![allow(clippy::manual_c_str_literals)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, HANDLE, HMODULE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetExitCodeThread, IsWow64Process,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
    LPTHREAD_START_ROUTINE, PROCESS_INFORMATION, STARTUPINFOW,
};

#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("PE 文件解析失败: {0}")]
    InvalidPe(String),
    #[error("Win32 API 调用失败 (错误码: {0}): {1}")]
    Win32(u32, &'static str),
    #[error("远程线程等待超时或异常")]
    RemoteThreadTimeout,
}

pub type Result<T> = std::result::Result<T, InjectorError>;

/// 目标程序 CPU 架构
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    Arm64,
}

/// 从字节切片解析 PE 架构
pub fn detect_architecture_from_bytes(bytes: &[u8]) -> Result<Architecture> {
    if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
        return Err(InjectorError::InvalidPe("缺少有效的 MZ DOS 签名".into()));
    }
    let pe_offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
    if pe_offset + 6 > bytes.len() {
        return Err(InjectorError::InvalidPe(format!(
            "PE 偏移溢出 (文件大小: {}, PE 偏移: {})",
            bytes.len(),
            pe_offset
        )));
    }
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(InjectorError::InvalidPe("缺少有效的 PE 签名 (PE\\0\\0)".into()));
    }

    let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
    match machine {
        0x014c => Ok(Architecture::X86),
        0x8664 => Ok(Architecture::X64),
        0xaa64 => Ok(Architecture::Arm64),
        other => Err(InjectorError::InvalidPe(format!(
            "不支持的机器架构代码: 0x{:04x}",
            other
        ))),
    }
}

pub mod shortcut;
pub use shortcut::resolve_shortcut;

/// 解析目标可执行文件的机器架构 (PE Machine Header)，支持自动解析 .lnk 快捷方式
pub fn detect_architecture<P: AsRef<Path>>(path: P) -> Result<Architecture> {
    let p = path.as_ref();
    let actual_path = if let Some((resolved, _)) = resolve_shortcut(p) {
        resolved
    } else {
        p.to_path_buf()
    };
    let bytes = std::fs::read(&actual_path)?;
    detect_architecture_from_bytes(&bytes)
}

/// 将 Rust 字符串转换为 Windows 宽字符 (UTF-16 带 Null 结尾)
fn to_wide_chars<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// 安全的 RAII 句柄守卫
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// 目标挂起进程 RAII 守卫：若在注入完成且主线程恢复执行前发生任何异常或提前返回，
/// 强制销毁挂起的目标进程，杜绝系统产生不可杀死的永久挂起僵尸进程
pub struct ProcessGuard {
    pub handle: HANDLE,
    disarmed: bool,
}

impl ProcessGuard {
    pub fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            disarmed: false,
        }
    }

    /// 标记注入与恢复完成，解除异常强制终止保护
    pub fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if !self.disarmed {
                unsafe {
                    TerminateProcess(self.handle, 1);
                }
            }
            unsafe { CloseHandle(self.handle) };
        }
    }
}

/// 为指定 Hook 动态库文件赋予 "ALL APPLICATION PACKAGES" (S-1-15-2-1) 读取与执行权限，
/// 确保在 UWP / AppContainer 沙箱隔离进程中调用 LoadLibraryW 时不会因权限不足而失败
pub fn grant_appcontainer_permissions<P: AsRef<Path>>(dll_path: P) -> Result<()> {
    let p = dll_path.as_ref();
    if !p.exists() {
        return Ok(());
    }
    let path_str = p.to_string_lossy();
    let status = std::process::Command::new("icacls")
        .args([path_str.as_ref(), "/grant", "*S-1-15-2-1:(RX)"])
        .status();

    if let Err(e) = status {
        tracing::warn!("调用 icacls 为 DLL 授予 AppContainer 读取权限失败: {}", e);
    }
    Ok(())
}

/// 为指定的 Windows UWP / WinStore 应用启用网络本地环回豁免 (Loopback Exemption)，
/// 突破 AppContainer 对 127.0.0.1 本地透明中继端口的访问阻断
pub fn enable_loopback_exemption(package_family_or_sid: &str) -> Result<()> {
    if package_family_or_sid.is_empty() {
        return Ok(());
    }
    let flag = if package_family_or_sid.starts_with("S-1-15-") {
        "-p"
    } else {
        "-n"
    };
    let status = std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", "-a", &format!("{}={}", flag, package_family_or_sid)])
        .status();

    match status {
        Ok(s) if s.success() => {
            tracing::info!("成功为 AppContainer [{}] 启用 Loopback 豁免", package_family_or_sid);
            Ok(())
        }
        Ok(s) => {
            tracing::warn!("CheckNetIsolation 返回非零退出码: {:?}", s.code());
            Ok(())
        }
        Err(e) => {
            tracing::warn!("调用 CheckNetIsolation.exe 失败: {}", e);
            Ok(())
        }
    }
}

/// 挂起启动目标程序并注入指定架构的 Hook 动态库
pub fn spawn_and_inject<P: AsRef<Path>>(target_exe: P, dll_path: P) -> Result<u32> {
    spawn_and_inject_with_args(target_exe, dll_path, None)
}

/// 挂起启动目标程序（携带命令行参数）并注入指定架构的 Hook 动态库，支持 .lnk 快捷方式
pub fn spawn_and_inject_with_args<P: AsRef<Path>>(
    target_exe: P,
    dll_path: P,
    cmd_args: Option<&str>,
) -> Result<u32> {
    let target_path = target_exe.as_ref();
    let dll_path = dll_path.as_ref();

    if !target_path.exists() {
        return Err(InjectorError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("目标文件不存在: {:?}", target_path),
        )));
    }
    if !dll_path.exists() {
        return Err(InjectorError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("待注入的动态库不存在: {:?}", dll_path),
        )));
    }

    // 自动为待注入 DLL 授权 ALL APPLICATION PACKAGES 权限，防止 AppContainer 隔离进程加载失败
    let _ = grant_appcontainer_permissions(dll_path);

    // 若目标为 .lnk 快捷方式，自动解析为真实可执行文件并智能合并启动参数
    let (resolved_target, combined_args) = if let Some((real_exe, lnk_args)) = resolve_shortcut(target_path) {
        let merged = match (lnk_args, cmd_args) {
            (Some(a1), Some(a2)) if !a2.trim().is_empty() => Some(format!("{} {}", a1.trim(), a2.trim())),
            (Some(a1), _) => Some(a1),
            (None, Some(a2)) if !a2.trim().is_empty() => Some(a2.trim().to_string()),
            _ => None,
        };
        (real_exe, merged)
    } else {
        (target_path.to_path_buf(), cmd_args.map(|s| s.to_string()))
    };

    let arch = detect_architecture(&resolved_target)?;
    tracing::info!("目标可执行程序架构: {:?}", arch);

    #[cfg(target_pointer_width = "64")]
    if arch == Architecture::X86 {
        return Err(InjectorError::InvalidPe(
            "架构不匹配: 目标程序是 32 位 (X86)，当前 64 位注入器无法直接注入，请调度 32 位专用注入模块".into()
        ));
    }
    #[cfg(target_pointer_width = "32")]
    if arch == Architecture::X64 || arch == Architecture::Arm64 {
        return Err(InjectorError::InvalidPe(format!(
            "架构不匹配: 目标程序是 64 位 ({:?})，当前 32 位注入器无法直接注入，请调度 64 位专用注入模块",
            arch
        )));
    }

    let target_wide = to_wide_chars(resolved_target.as_os_str());
    let dll_wide = to_wide_chars(dll_path.as_os_str());
    let dll_size_bytes = dll_wide.len() * std::mem::size_of::<u16>();

    let full_cmd = match &combined_args {
        Some(args) if !args.trim().is_empty() => {
            format!("\"{}\" {}", resolved_target.display(), args.trim())
        }
        _ => format!("\"{}\"", resolved_target.display()),
    };
    let mut cmdline_wide = to_wide_chars(OsStr::new(&full_cmd));

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // 彻底清除进程级 HTTP_PROXY / HTTPS_PROXY 环境变量，
        // 强制目标程序以为直连公网，从而触发 Winsock Fake-IP 与 TCP 透明捕获
        for var in &[
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
        ] {
            std::env::remove_var(var);
        }

        let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !k32.is_null() {
            if let Some(p) = GetProcAddress(k32, b"SetEnvironmentVariableW\0".as_ptr()) {
                let set_env: unsafe extern "system" fn(*const u16, *const u16) -> BOOL = std::mem::transmute(p);
                for var in &[
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
                    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
                ] {
                    let w: Vec<u16> = var.encode_utf16().chain(std::iter::once(0)).collect();
                    set_env(w.as_ptr(), std::ptr::null());
                }
            }
        }

        // 1. 挂起启动目标进程 (CREATE_SUSPENDED | CREATE_NEW_CONSOLE 保障控制台程序窗口可见)
        let success: BOOL = CreateProcessW(
            target_wide.as_ptr(),
            cmdline_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            std::ptr::null_mut(),
            std::ptr::null(),
            &si,
            &mut pi,
        );

        if success == 0 {
            return Err(InjectorError::Win32(GetLastError(), "CreateProcessW"));
        }

        let mut proc_guard = ProcessGuard::new(pi.hProcess);
        let thread_guard = HandleGuard(pi.hThread);

        // 2. 在目标进程空间中分配内存写入 DLL 绝对路径
        let remote_mem = VirtualAllocEx(
            pi.hProcess,
            std::ptr::null_mut(),
            dll_size_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(InjectorError::Win32(GetLastError(), "VirtualAllocEx"));
        }

        // 3. 将 DLL 路径写入目标内存
        let mut bytes_written = 0;
        let write_ok = WriteProcessMemory(
            pi.hProcess,
            remote_mem,
            dll_wide.as_ptr() as *const c_void,
            dll_size_bytes,
            &mut bytes_written,
        );
        if write_ok == 0 || bytes_written != dll_size_bytes {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "WriteProcessMemory"));
        }

        // 4. 获取 kernel32!LoadLibraryW 真实地址
        let kernel32_mod: HMODULE = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32_mod.is_null() {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "GetModuleHandleA"));
        }
        let load_lib_proc = GetProcAddress(kernel32_mod, b"LoadLibraryW\0".as_ptr());
        if load_lib_proc.is_none() {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "GetProcAddress"));
        }

        // 5. 创建远程线程启动 LoadLibraryW
        let start_routine: LPTHREAD_START_ROUTINE = std::mem::transmute(load_lib_proc);
        let remote_thread = CreateRemoteThread(
            pi.hProcess,
            std::ptr::null_mut(),
            0,
            start_routine,
            remote_mem,
            0,
            std::ptr::null_mut(),
        );
        if remote_thread.is_null() {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "CreateRemoteThread"));
        }
        let remote_thread_guard = HandleGuard(remote_thread);

        // 6. 等待注入线程执行完毕 (最多等待 10 秒)
        let wait_res = WaitForSingleObject(remote_thread, 10000);
        if wait_res != WAIT_OBJECT_0 {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::RemoteThreadTimeout);
        }

        let mut load_lib_ret = 0u32;
        GetExitCodeThread(remote_thread, &mut load_lib_ret);
        tracing::info!("远程注入线程退出码 (LoadLibraryW 返回基址低32位): 0x{:x}", load_lib_ret);
        if load_lib_ret == 0 {
            VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "远程进程执行 LoadLibraryW 失败返回 NULL"));
        }

        // 7. 释放分配的 DLL 路径字符串内存
        VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);

        // 8. 恢复目标进程主线程运行
        let resume_res = ResumeThread(pi.hThread);
        if resume_res == u32::MAX {
            return Err(InjectorError::Win32(GetLastError(), "ResumeThread"));
        }

        // 目标进程已安全恢复运行，解除异常强杀保护
        proc_guard.disarm();

        drop(remote_thread_guard);
        drop(thread_guard);
        drop(proc_guard);

        tracing::info!("注入完成，目标程序 PID: {} 已恢复执行", pi.dwProcessId);
        Ok(pi.dwProcessId)
    }
}

/// 向已存在的运行中进程注入指定架构的 Hook 动态库
pub fn inject_existing_pid<P: AsRef<Path>>(pid: u32, dll_path: P) -> Result<()> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let dll_p = dll_path.as_ref();
    if !dll_p.exists() {
        return Err(InjectorError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("待注入的动态库不存在: {:?}", dll_p),
        )));
    }

    let _ = grant_appcontainer_permissions(dll_p);

    let dll_wide = to_wide_chars(dll_p.as_os_str());
    let dll_size_bytes = dll_wide.len() * std::mem::size_of::<u16>();

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            pid,
        );

        if process_handle.is_null() {
            return Err(InjectorError::Win32(GetLastError(), "OpenProcess"));
        }
        let proc_guard = HandleGuard(process_handle);

        let mut is_wow64: BOOL = 0;
        if IsWow64Process(process_handle, &mut is_wow64) != 0 {
            #[cfg(target_pointer_width = "64")]
            if is_wow64 != 0 {
                return Err(InjectorError::InvalidPe(format!(
                    "架构不匹配: PID {} 为 32 位 (WOW64) 进程，当前 64 位注入器无法直接注入，请调度 32 位专用模块",
                    pid
                )));
            }
        }

        let remote_mem = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            dll_size_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(InjectorError::Win32(GetLastError(), "VirtualAllocEx"));
        }

        let mut bytes_written = 0;
        let write_ok = WriteProcessMemory(
            process_handle,
            remote_mem,
            dll_wide.as_ptr() as *const c_void,
            dll_size_bytes,
            &mut bytes_written,
        );
        if write_ok == 0 || bytes_written != dll_size_bytes {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "WriteProcessMemory"));
        }

        let kernel32_mod = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32_mod.is_null() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "GetModuleHandleA"));
        }
        let load_lib_proc = GetProcAddress(kernel32_mod, b"LoadLibraryW\0".as_ptr());
        if load_lib_proc.is_none() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "GetProcAddress"));
        }

        let start_routine: LPTHREAD_START_ROUTINE = std::mem::transmute(load_lib_proc);
        let remote_thread = CreateRemoteThread(
            process_handle,
            std::ptr::null_mut(),
            0,
            start_routine,
            remote_mem,
            0,
            std::ptr::null_mut(),
        );
        if remote_thread.is_null() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::Win32(GetLastError(), "CreateRemoteThread"));
        }
        let remote_thread_guard = HandleGuard(remote_thread);

        let wait_res = WaitForSingleObject(remote_thread, 5000);
        if wait_res != WAIT_OBJECT_0 {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            return Err(InjectorError::RemoteThreadTimeout);
        }

        let mut load_lib_ret = 0u32;
        GetExitCodeThread(remote_thread, &mut load_lib_ret);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

        drop(remote_thread_guard);
        drop(proc_guard);

        if load_lib_ret == 0 {
            return Err(InjectorError::Win32(GetLastError(), "远程进程执行 LoadLibraryW 失败"));
        }

        tracing::info!("成功向 PID {} 动态注入 Hook 动态库", pid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_detect_x86_valid() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes()); // PE offset = 64
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(&0x014cu16.to_le_bytes()); // Machine = i386

        let arch = detect_architecture_from_bytes(&data).unwrap();
        assert_eq!(arch, Architecture::X86);
    }

    #[test]
    fn test_pe_detect_x64_valid() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes()); // PE offset = 64
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = AMD64

        let arch = detect_architecture_from_bytes(&data).unwrap();
        assert_eq!(arch, Architecture::X64);
    }

    #[test]
    fn test_pe_detect_arm64_valid() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(&0xaa64u16.to_le_bytes());

        let arch = detect_architecture_from_bytes(&data).unwrap();
        assert_eq!(arch, Architecture::Arm64);
    }

    #[test]
    fn test_pe_detect_missing_mz() {
        let data = vec![0u8; 128];
        let err = detect_architecture_from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("缺少有效的 MZ"));
    }

    #[test]
    fn test_pe_detect_truncated_offset() {
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&1000u32.to_le_bytes()); // 偏移量超出长度
        let err = detect_architecture_from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("PE 偏移溢出"));
    }

    #[test]
    fn test_pe_detect_missing_pe_magic() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..68].copy_from_slice(b"FAIL");
        let err = detect_architecture_from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("缺少有效的 PE 签名"));
    }

    #[test]
    fn test_pe_detect_real_system32_cmd() {
        // 在 Windows 环境测试真实系统文件 cmd.exe
        let cmd_path = "C:\\Windows\\System32\\cmd.exe";
        if Path::new(cmd_path).exists() {
            let arch = detect_architecture(cmd_path).unwrap();
            assert!(arch == Architecture::X64 || arch == Architecture::Arm64);
        }
    }

    #[test]
    fn test_spawn_and_inject_rejects_mismatched_arch() {
        let temp_exe = std::env::temp_dir().join("shadow_test_mock_x86.exe");
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        std::fs::write(&temp_exe, &data).unwrap();

        let dummy_dll = std::env::temp_dir().join("dummy_hook.dll");
        std::fs::write(&dummy_dll, b"dummy").unwrap();

        #[cfg(target_pointer_width = "64")]
        {
            let res = spawn_and_inject(&temp_exe, &dummy_dll);
            assert!(res.is_err());
            let err_msg = res.unwrap_err().to_string();
            assert!(err_msg.contains("架构不匹配"), "错误信息不符合预期: {}", err_msg);
        }

        let _ = std::fs::remove_file(temp_exe);
        let _ = std::fs::remove_file(dummy_dll);
    }

    #[test]
    fn test_process_guard_terminates_suspended_process() {
        let cmd_path = "C:\\Windows\\System32\\cmd.exe";
        if !Path::new(cmd_path).exists() {
            return;
        }

        let cmd_wide = to_wide_chars(cmd_path);
        let mut cmdline_wide = to_wide_chars("\"C:\\Windows\\System32\\cmd.exe\"");

        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let success = CreateProcessW(
                cmd_wide.as_ptr(),
                cmdline_wide.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null_mut(),
                std::ptr::null(),
                &si,
                &mut pi,
            );
            assert_ne!(success, 0, "启动挂起测试进程失败");

            let h_proc_raw = pi.hProcess;
            let thread_guard = HandleGuard(pi.hThread);

            // 用作用域模拟注入提前出错导致 ProcessGuard drop
            {
                let _proc_guard = ProcessGuard::new(h_proc_raw);
                // 不调用 disarm()，正常离开作用域自动执行 TerminateProcess + CloseHandle
            }

            drop(thread_guard);

            // 重新打开进程句柄验证其已被终止 (退出码为 1)
            use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
            let proc_check = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pi.dwProcessId);
            if !proc_check.is_null() {
                let mut exit_code = 0u32;
                GetExitCodeProcess(proc_check, &mut exit_code);
                assert_eq!(exit_code, 1, "进程应当已被 TerminateProcess(1) 强制终止");
                CloseHandle(proc_check);
            }
        }
    }

    #[test]
    fn test_appcontainer_permissions_and_loopback_exemption() {
        let temp_dll = std::env::temp_dir().join("shadow_test_appcontainer.dll");
        std::fs::write(&temp_dll, b"mock dll binary content").unwrap();

        // 验证执行权限授予逻辑不发生 panic
        let res = grant_appcontainer_permissions(&temp_dll);
        assert!(res.is_ok());

        // 验证 Loopback 豁免接口对空参数的短路安全防御
        assert!(enable_loopback_exemption("").is_ok());

        let _ = std::fs::remove_file(temp_dll);
    }
}
