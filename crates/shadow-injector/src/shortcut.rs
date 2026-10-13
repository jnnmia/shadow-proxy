//! shortcut.rs: Windows .lnk 快捷方式与 Shell 链接解析器
//!
//! 利用 Win32 COM (IShellLinkW / IPersistFile) 解析桌面与开始菜单快捷方式，
//! 提取真实目标可执行文件路径与默认启动参数。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::core::GUID;
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};

const CLSID_SHELL_LINK: GUID = GUID {
    data1: 0x00021401,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_ISHELL_LINK_W: GUID = GUID {
    data1: 0x000214F9,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_IPERSIST_FILE: GUID = GUID {
    data1: 0x0000010b,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut c_void) -> u32,
    release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

#[repr(C)]
struct IPersistFileVtbl {
    unknown: IUnknownVtbl,
    get_class_id: unsafe extern "system" fn(this: *mut c_void, p_class_id: *mut GUID) -> i32,
    is_dirty: unsafe extern "system" fn(this: *mut c_void) -> i32,
    load: unsafe extern "system" fn(this: *mut c_void, psz_file_name: *const u16, dw_mode: u32) -> i32,
}

#[repr(C)]
struct IShellLinkWVtbl {
    unknown: IUnknownVtbl,
    get_path: unsafe extern "system" fn(
        this: *mut c_void,
        psz_file: *mut u16,
        cch_max_path: i32,
        pfd: *mut c_void,
        f_flags: u32,
    ) -> i32,
    get_id_list: *const c_void,
    set_id_list: *const c_void,
    get_description: *const c_void,
    set_description: *const c_void,
    get_working_directory: *const c_void,
    set_working_directory: *const c_void,
    get_arguments: unsafe extern "system" fn(
        this: *mut c_void,
        psz_args: *mut u16,
        cch_max_path: i32,
    ) -> i32,
}

/// 解析 Windows 快捷方式 (.lnk) 的目标文件路径及附带参数
pub fn resolve_shortcut<P: AsRef<Path>>(shortcut_path: P) -> Option<(PathBuf, Option<String>)> {
    let p = shortcut_path.as_ref();
    if !p.exists() {
        return None;
    }
    let ext = p.extension()?.to_str()?.to_lowercase();
    if ext != "lnk" {
        return None;
    }

    let mut current = p.to_path_buf();
    let mut final_args: Option<String> = None;

    // 支持多层快捷方式嵌套解析（最多追踪 5 层）
    for _ in 0..5 {
        if !current.exists() {
            return None;
        }
        let ext = current.extension()?.to_str()?.to_lowercase();
        if ext != "lnk" {
            break;
        }

        if let Some((target, args)) = resolve_single_lnk(&current) {
            if final_args.is_none() && args.is_some() {
                final_args = args;
            }
            current = target;
        } else {
            return None;
        }
    }

    Some((current, final_args))
}

/// 解析单个 .lnk 文件
fn resolve_single_lnk(lnk_path: &Path) -> Option<(PathBuf, Option<String>)> {
    unsafe {
        // 初始化 COM 环境
        let _ = CoInitializeEx(std::ptr::null_mut(), COINIT_MULTITHREADED as u32);

        let mut shell_link_ptr: *mut c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_SHELL_LINK,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ISHELL_LINK_W,
            &mut shell_link_ptr,
        );
        if hr != 0 || shell_link_ptr.is_null() {
            CoUninitialize();
            return None;
        }

        let shell_link_vtbl = *(shell_link_ptr as *const *const IShellLinkWVtbl);

        let mut persist_file_ptr: *mut c_void = std::ptr::null_mut();
        let hr = ((*shell_link_vtbl).unknown.query_interface)(
            shell_link_ptr,
            &IID_IPERSIST_FILE,
            &mut persist_file_ptr,
        );
        if hr != 0 || persist_file_ptr.is_null() {
            ((*shell_link_vtbl).unknown.release)(shell_link_ptr);
            CoUninitialize();
            return None;
        }

        let persist_file_vtbl = *(persist_file_ptr as *const *const IPersistFileVtbl);

        let wide_path: Vec<u16> = lnk_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let load_hr = ((*persist_file_vtbl).load)(persist_file_ptr, wide_path.as_ptr(), 0);

        let mut result = None;
        if load_hr == 0 {
            let mut target_buf = [0u16; 1024];
            let get_path_hr = ((*shell_link_vtbl).get_path)(
                shell_link_ptr,
                target_buf.as_mut_ptr(),
                target_buf.len() as i32,
                std::ptr::null_mut(),
                0,
            );

            if get_path_hr == 0 {
                let len = target_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(target_buf.len());
                let target_str = String::from_utf16_lossy(&target_buf[..len]);
                if !target_str.trim().is_empty() {
                    let target_path = PathBuf::from(target_str.trim());

                    let mut args_buf = [0u16; 1024];
                    let args_hr = ((*shell_link_vtbl).get_arguments)(
                        shell_link_ptr,
                        args_buf.as_mut_ptr(),
                        args_buf.len() as i32,
                    );
                    let args_opt = if args_hr == 0 {
                        let arg_len = args_buf
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(args_buf.len());
                        let args_str = String::from_utf16_lossy(&args_buf[..arg_len]);
                        let trimmed = args_str.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    } else {
                        None
                    };

                    result = Some((target_path, args_opt));
                }
            }
        }

        ((*persist_file_vtbl).unknown.release)(persist_file_ptr);
        ((*shell_link_vtbl).unknown.release)(shell_link_ptr);
        CoUninitialize();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_lnk_file_returns_none() {
        let fake = Path::new("C:\\Windows\\System32\\cmd.exe");
        // 对于非 .lnk 文件，resolve_shortcut 判定无需解析，返回 None 或者自身
        assert!(resolve_shortcut(fake).is_none());
    }

    #[test]
    fn test_real_system_lnk_resolution() {
        let temp_lnk = std::env::temp_dir().join("shadow_test_shortcut_eval.lnk");
        let _ = std::fs::remove_file(&temp_lnk);

        // 使用 PowerShell 动态生成一个标准 Windows .lnk 快捷方式
        let script = format!(
            "$ws = New-Object -ComObject WScript.Shell; \
             $s = $ws.CreateShortcut('{}'); \
             $s.TargetPath = 'C:\\Windows\\System32\\cmd.exe'; \
             $s.Arguments = '/c echo test'; \
             $s.Save()",
            temp_lnk.display()
        );

        use std::os::windows::process::CommandExt;
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .creation_flags(0x0800_0000)
            .status();

        if let Ok(s) = status {
            if s.success() && temp_lnk.exists() {
                let resolved = resolve_shortcut(&temp_lnk);
                assert!(resolved.is_some(), "必须成功解析动态创建的快捷方式");
                let (target, args) = resolved.unwrap();
                assert!(target.to_string_lossy().to_lowercase().contains("cmd.exe"));
                assert_eq!(args.as_deref(), Some("/c echo test"));
            }
        }
        let _ = std::fs::remove_file(temp_lnk);
    }
}
