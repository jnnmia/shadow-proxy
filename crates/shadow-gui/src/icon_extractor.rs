//! icon_extractor: 目标程序原生图标提取器
//! 基于 Windows 原生 Shell API 与 GDI+ 将可执行文件的主图标转为 Base64 PNG Data URL。

#![allow(clippy::manual_c_str_literals)]

use std::ffi::c_void;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[repr(C)]
#[derive(Copy, Clone)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// Windows GDI+ PNG Encoder CLSID: 557cf406-1a04-11d3-9a73-0000f81ef32e
const CLSID_PNG: Guid = Guid {
    data1: 0x557cf406,
    data2: 0x1a04,
    data3: 0x11d3,
    data4: [0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e],
};

#[repr(C)]
struct GdiplusStartupInput {
    gdiplus_version: u32,
    debug_event_callback: *mut c_void,
    suppress_background_thread: i32,
    suppress_external_codecs: i32,
}

#[repr(C)]
struct Shfileinfow {
    h_icon: *mut c_void,
    i_icon: i32,
    dw_attributes: u32,
    sz_display_name: [u16; 260],
    sz_type_name: [u16; 80],
}

const SHGFI_ICON: u32 = 0x000000100;
const SHGFI_LARGEICON: u32 = 0x000000000;

/// 将路径字符串转为 UTF-16 宽字符并追加空结尾
fn to_wide_chars<P: AsRef<Path>>(path: P) -> Vec<u16> {
    let os_str: &OsStr = path.as_ref().as_os_str();
    os_str.encode_wide().chain(std::iter::once(0)).collect()
}

/// 标准 RFC 4648 Base64 纯 Safe 编码实现
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

static GDI_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 从指定 Windows 可执行文件或关联路径中提取原生图标，并转换为透明 Data URL (PNG Base64)
pub fn extract_icon_as_base64_png<P: AsRef<Path>>(path: P) -> Option<String> {
    let path_ref = path.as_ref();
    if !path_ref.exists() {
        return None;
    }

    let _guard = GDI_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        // 1. 动态获取 Shell 与 User32 相关函数句柄
        let shell32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"shell32.dll\0".as_ptr());
        let user32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"user32.dll\0".as_ptr());
        let gdiplus = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"gdiplus.dll\0".as_ptr());
        let ole32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"ole32.dll\0".as_ptr());
        let kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr());

        if shell32.is_null() || user32.is_null() || gdiplus.is_null() || ole32.is_null() || kernel32.is_null() {
            return None;
        }

        // 2. 解析 API 地址
        let fn_sh_get_file_info: unsafe extern "system" fn(*const u16, u32, *mut Shfileinfow, u32, u32) -> usize =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                shell32,
                b"SHGetFileInfoW\0".as_ptr(),
            )?);
        let fn_destroy_icon: unsafe extern "system" fn(*mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                user32,
                b"DestroyIcon\0".as_ptr(),
            )?);
        let fn_gdiplus_startup: unsafe extern "system" fn(*mut usize, *const GdiplusStartupInput, *mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                gdiplus,
                b"GdiplusStartup\0".as_ptr(),
            )?);
        let fn_gdiplus_shutdown: unsafe extern "system" fn(usize) =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                gdiplus,
                b"GdiplusShutdown\0".as_ptr(),
            )?);
        let fn_create_bitmap: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                gdiplus,
                b"GdipCreateBitmapFromHICON\0".as_ptr(),
            )?);
        let fn_save_image_stream: unsafe extern "system" fn(*mut c_void, *mut c_void, *const Guid, *const c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                gdiplus,
                b"GdipSaveImageToStream\0".as_ptr(),
            )?);
        let fn_dispose_image: unsafe extern "system" fn(*mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                gdiplus,
                b"GdipDisposeImage\0".as_ptr(),
            )?);
        let fn_create_stream: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                ole32,
                b"CreateStreamOnHGlobal\0".as_ptr(),
            )?);
        let fn_get_hglobal: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                ole32,
                b"GetHGlobalFromStream\0".as_ptr(),
            )?);
        let fn_global_size: unsafe extern "system" fn(*mut c_void) -> usize =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                kernel32,
                b"GlobalSize\0".as_ptr(),
            )?);
        let fn_global_lock: unsafe extern "system" fn(*mut c_void) -> *const u8 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                kernel32,
                b"GlobalLock\0".as_ptr(),
            )?);
        let fn_global_unlock: unsafe extern "system" fn(*mut c_void) -> i32 =
            std::mem::transmute(windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                kernel32,
                b"GlobalUnlock\0".as_ptr(),
            )?);

        // 3. 提取目标程序 HICON
        let path_w = to_wide_chars(path_ref);
        let mut shfi: Shfileinfow = std::mem::zeroed();
        let ret = fn_sh_get_file_info(
            path_w.as_ptr(),
            0,
            &mut shfi,
            std::mem::size_of::<Shfileinfow>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        );

        if ret == 0 || shfi.h_icon.is_null() {
            return None;
        }

        let h_icon = shfi.h_icon;

        // 4. 初始化 GDI+ 环境
        let mut token: usize = 0;
        let input = GdiplusStartupInput {
            gdiplus_version: 1,
            debug_event_callback: std::ptr::null_mut(),
            suppress_background_thread: 0,
            suppress_external_codecs: 0,
        };

        if fn_gdiplus_startup(&mut token, &input, std::ptr::null_mut()) != 0 {
            fn_destroy_icon(h_icon);
            return None;
        }

        // 5. 将 HICON 转换为 Gdiplus Bitmap
        let mut p_bitmap: *mut c_void = std::ptr::null_mut();
        if fn_create_bitmap(h_icon, &mut p_bitmap) != 0 || p_bitmap.is_null() {
            fn_destroy_icon(h_icon);
            fn_gdiplus_shutdown(token);
            return None;
        }

        // 6. 创建内存 IStream 并保存为 PNG 格式
        let mut p_stream: *mut c_void = std::ptr::null_mut();
        let mut result_data_url = None;

        if fn_create_stream(std::ptr::null_mut(), 1, &mut p_stream) == 0 && !p_stream.is_null() {
            if fn_save_image_stream(p_bitmap, p_stream, &CLSID_PNG, std::ptr::null()) == 0 {
                let mut h_global: *mut c_void = std::ptr::null_mut();
                if fn_get_hglobal(p_stream, &mut h_global) == 0 && !h_global.is_null() {
                    let size = fn_global_size(h_global);
                    if size > 0 {
                        let ptr = fn_global_lock(h_global);
                        if !ptr.is_null() {
                            let bytes = std::slice::from_raw_parts(ptr, size);
                            // 校验是否为合法 PNG 签名 (\x89PNG\r\n\x1a\n)
                            if bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" {
                                let b64 = base64_encode(bytes);
                                result_data_url = Some(format!("data:image/png;base64,{}", b64));
                            }
                            fn_global_unlock(h_global);
                        }
                    }
                }
            }

            // COM IStream::Release (虚表第 3 个函数指针)
            if !p_stream.is_null() {
                let vtable = *(p_stream as *mut *mut usize);
                let fn_release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtable.add(2));
                fn_release(p_stream);
            }
        }

        // 7. 优雅释放资源
        fn_dispose_image(p_bitmap);
        fn_destroy_icon(h_icon);
        fn_gdiplus_shutdown(token);

        result_data_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_basic() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_extract_icon_non_existent_file() {
        let res = extract_icon_as_base64_png("C:\\this_file_does_not_exist_12345.exe");
        assert!(res.is_none());
    }

    #[test]
    fn test_extract_icon_real_system_cmd() {
        let cmd_path = "C:\\Windows\\System32\\cmd.exe";
        if Path::new(cmd_path).exists() {
            let res = extract_icon_as_base64_png(cmd_path);
            assert!(res.is_some(), "应当能从系统 cmd.exe 成功提取图标");
            let data_url = res.unwrap();
            assert!(
                data_url.starts_with("data:image/png;base64,"),
                "输出应当是合法的 PNG Data URL: {}",
                &data_url[..30]
            );
            assert!(data_url.len() > 100, "PNG Base64 长度应当充足");
        }
    }

    #[test]
    fn test_extract_icon_concurrent_safety() {
        let cmd_path = "C:\\Windows\\System32\\cmd.exe";
        if Path::new(cmd_path).exists() {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let p = cmd_path.to_string();
                handles.push(std::thread::spawn(move || {
                    let res = extract_icon_as_base64_png(&p);
                    assert!(res.is_some(), "多线程并发提取系统 cmd.exe 图标应当成功");
                    let data = res.unwrap();
                    assert!(data.starts_with("data:image/png;base64,"));
                }));
            }
            for h in handles {
                h.join().expect("并发线程执行无 Panic");
            }
        }
    }
}
