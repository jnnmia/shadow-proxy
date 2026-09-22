//! ghost-hook/iat: PE 导入地址表 (IAT) 遍历与原子重定向钩子 (支持函数名与 Ordinal 序号)

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

pub static OUR_MODULE_BASE: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _reserved: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

pub struct HookDef {
    pub dll_name: &'static str,
    pub func_name: &'static str,
    pub ordinal: u16,
    pub hook_addr: usize,
    pub orig_addr: &'static AtomicUsize,
}

/// 解析单模块 PE 结构并对目标导入函数执行 IAT 指针重定向
pub unsafe fn hook_module_iat(base_addr: usize, hooks: &[HookDef]) {
    if base_addr == 0 || base_addr == OUR_MODULE_BASE.load(Ordering::Relaxed) {
        return;
    }

    let dos_header = &*(base_addr as *const ImageDosHeader);
    if dos_header.e_magic != 0x5A4D {
        return;
    }

    let nt_ptr = (base_addr as isize + dos_header.e_lfanew as isize) as *const u8;
    let signature = *(nt_ptr as *const u32);
    if signature != 0x00004550 {
        return;
    }

    let magic = *((nt_ptr.add(24)) as *const u16);
    let import_dir_offset = match magic {
        0x10B => 24 + 96 + 8,  // 32 位 PE32 OptionalHeader (DataDirectory[1])
        0x20B => 24 + 112 + 8, // 64 位 PE32+ OptionalHeader (DataDirectory[1])
        _ => return,
    };

    let import_dir = &*(nt_ptr.add(import_dir_offset) as *const ImageDataDirectory);
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return;
    }

    let mut desc = (base_addr + import_dir.virtual_address as usize) as *const ImageImportDescriptor;

    while (*desc).name != 0 {
        let name_ptr = (base_addr + (*desc).name as usize) as *const c_char;
        let dll_name_str = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => {
                desc = desc.add(1);
                continue;
            }
        };

        for hook in hooks {
            if dll_name_matches(dll_name_str, hook.dll_name) {
                apply_hook_to_descriptor(base_addr, desc, hook, magic == 0x20B);
            }
        }

        desc = desc.add(1);
    }
}

fn dll_name_matches(imported_dll: &str, target_dll: &str) -> bool {
    if imported_dll.eq_ignore_ascii_case(target_dll) {
        return true;
    }
    if target_dll.eq_ignore_ascii_case("kernel32.dll") {
        let lower = imported_dll.to_ascii_lowercase();
        return lower == "kernelbase.dll"
            || lower.starts_with("api-ms-win-core-processthreads")
            || lower.starts_with("api-ms-win-core-libraryloader")
            || lower.starts_with("api-ms-win-core-synch");
    }
    if target_dll.eq_ignore_ascii_case("ws2_32.dll") {
        let lower = imported_dll.to_ascii_lowercase();
        return lower == "wsock32.dll";
    }
    false
}

unsafe fn apply_hook_to_descriptor(
    base: usize,
    desc: *const ImageImportDescriptor,
    hook: &HookDef,
    is_64bit: bool,
) {
    let thunk_rva = if (*desc).original_first_thunk != 0 {
        (*desc).original_first_thunk
    } else {
        (*desc).first_thunk
    };

    let step = if is_64bit { 8 } else { 4 };
    let mut orig_thunk = (base + thunk_rva as usize) as *const u8;
    let mut iat_thunk = (base + (*desc).first_thunk as usize) as *mut usize;

    loop {
        let is_ordinal = if is_64bit {
            let val = *(orig_thunk as *const u64);
            if val == 0 {
                break;
            }
            (val & 0x8000_0000_0000_0000) != 0
        } else {
            let val = *(orig_thunk as *const u32);
            if val == 0 {
                break;
            }
            (val & 0x8000_0000) != 0
        };

        let mut matched = false;

        if is_ordinal {
            let ord = if is_64bit {
                (*(orig_thunk as *const u64) & 0xFFFF) as u16
            } else {
                (*(orig_thunk as *const u32) & 0xFFFF) as u16
            };
            if hook.ordinal != 0 && ord == hook.ordinal {
                matched = true;
            }
        } else {
            let name_rva = if is_64bit {
                *(orig_thunk as *const u64) as usize
            } else {
                *(orig_thunk as *const u32) as usize
            };

            // 边界守护：校验 name_rva 范围，防止畸形 PE 导致非法指针解引用 (0xC0000005)
            if name_rva != 0 && name_rva < 0x4000_0000 {
                // IMAGE_IMPORT_BY_NAME: Hint (2 bytes), Name (null-terminated ASCII)
                let func_name_ptr = (base + name_rva + 2) as *const c_char;
                if let Ok(func_name) = std::ffi::CStr::from_ptr(func_name_ptr).to_str() {
                    if func_name == hook.func_name {
                        matched = true;
                    }
                }
            }
        }

        if matched {
            let current_target = *iat_thunk;
            if current_target != hook.hook_addr {
                // 首次拦截保存真实原始地址
                if hook.orig_addr.load(Ordering::Relaxed) == 0 {
                    hook.orig_addr.store(current_target, Ordering::Relaxed);
                }

                let mut old_protect = 0u32;
                if VirtualProtect(
                    iat_thunk as *mut c_void,
                    step,
                    PAGE_READWRITE,
                    &mut old_protect,
                ) != 0
                {
                    *iat_thunk = hook.hook_addr;
                    VirtualProtect(
                        iat_thunk as *mut c_void,
                        step,
                        old_protect,
                        &mut old_protect,
                    );
                    FlushInstructionCache(
                        GetCurrentProcess(),
                        iat_thunk as *const c_void,
                        step,
                    );
                }
            }
            break;
        }

        orig_thunk = orig_thunk.add(step);
        iat_thunk = ((iat_thunk as usize) + step) as *mut usize;
    }
}

fn is_system_core_module(sz_module: &[u16]) -> bool {
    let len = sz_module.iter().position(|&c| c == 0).unwrap_or(sz_module.len());
    let name = String::from_utf16_lossy(&sz_module[..len]).to_ascii_lowercase();
    name == "ntdll.dll"
        || name == "kernel32.dll"
        || name == "kernelbase.dll"
        || name == "ws2_32.dll"
        || name == "shadow_hook.dll"
        || name == "shadow_hook32.dll"
        || name == "ghost_hook.dll"
        || name == "ghost_hook32.dll"
}

/// 扫描当前进程加载的所有模块并批量打桩
pub unsafe fn hook_all_loaded_modules(hooks: &[HookDef]) {
    let snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId(),
    );
    if snap == INVALID_HANDLE_VALUE {
        return;
    }

    let mut entry: MODULEENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snap, &mut entry) != 0 {
        loop {
            if !is_system_core_module(&entry.szModule) {
                hook_module_iat(entry.modBaseAddr as usize, hooks);
            }
            if Module32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snap);
}
