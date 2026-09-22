//! ghost-hook/winsock_hook: Winsock C-ABI 拦截桩、Fake-IP 注入与 QUIC/DNS 防泄漏

#![allow(clippy::missing_safety_doc, clippy::manual_c_str_literals)]

use crate::fakeip;
use crate::iat::{self, HookDef};
use crate::protocol::HookTarget;
use std::ffi::{c_char, c_void};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{FARPROC, HMODULE};
use windows_sys::Win32::Networking::WinSock::{
    getpeername, getsockopt, send, AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET,
    SOCKET_ERROR, SOCK_DGRAM, SOL_SOCKET, SO_TYPE, WSAECONNREFUSED, WSAEWOULDBLOCK,
    WSAGetLastError, WSASetLastError,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

pub static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_WSACONNECT: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_GETADDRINFO: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_GETADDRINFOW: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_SENDTO: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_WSASENDTO: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_WSAIOCTL: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_CONNECTEX: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_WSASEND: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_SEND: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_CLOSESOCKET: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_GETPROCADDRESS: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_LOADLIBRARYW: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_LOADLIBRARYA: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_LOADLIBRARYEXW: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_LOADLIBRARYEXA: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_CREATEPROCESSW: AtomicUsize = AtomicUsize::new(0);
pub static ORIG_CREATEPROCESSA: AtomicUsize = AtomicUsize::new(0);

pub static RELAY_PORT: AtomicU16 = AtomicU16::new(10808);
pub static STRICT_DNS: AtomicBool = AtomicBool::new(true);

#[repr(C)]
pub struct AddrInfoW {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: *mut u16,
    pub ai_addr: *mut SOCKADDR,
    pub ai_next: *mut AddrInfoW,
}

#[repr(C)]
pub struct AddrInfoA {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: *mut c_char,
    pub ai_addr: *mut SOCKADDR,
    pub ai_next: *mut AddrInfoA,
}

pub unsafe fn build_hooks() -> [HookDef; 17] {
    [
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "connect",
            ordinal: 4,
            hook_addr: hooked_connect as *const () as usize,
            orig_addr: &ORIG_CONNECT,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "WSAConnect",
            ordinal: 46,
            hook_addr: hooked_wsaconnect as *const () as usize,
            orig_addr: &ORIG_WSACONNECT,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "GetAddrInfoW",
            ordinal: 31,
            hook_addr: hooked_getaddrinfow as *const () as usize,
            orig_addr: &ORIG_GETADDRINFOW,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "getaddrinfo",
            ordinal: 192,
            hook_addr: hooked_getaddrinfo as *const () as usize,
            orig_addr: &ORIG_GETADDRINFO,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "sendto",
            ordinal: 20,
            hook_addr: hooked_sendto as *const () as usize,
            orig_addr: &ORIG_SENDTO,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "WSASendTo",
            ordinal: 73,
            hook_addr: hooked_wsasendto as *const () as usize,
            orig_addr: &ORIG_WSASENDTO,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "WSAIoctl",
            ordinal: 67,
            hook_addr: hooked_wsapioctl as *const () as usize,
            orig_addr: &ORIG_WSAIOCTL,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "WSASend",
            ordinal: 72,
            hook_addr: hooked_wsasend as *const () as usize,
            orig_addr: &ORIG_WSASEND,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "send",
            ordinal: 19,
            hook_addr: hooked_send as *const () as usize,
            orig_addr: &ORIG_SEND,
        },
        HookDef {
            dll_name: "ws2_32.dll",
            func_name: "closesocket",
            ordinal: 3,
            hook_addr: hooked_closesocket as *const () as usize,
            orig_addr: &ORIG_CLOSESOCKET,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "GetProcAddress",
            ordinal: 0,
            hook_addr: hooked_getprocaddress as *const () as usize,
            orig_addr: &ORIG_GETPROCADDRESS,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "LoadLibraryW",
            ordinal: 0,
            hook_addr: hooked_loadlibraryw as *const () as usize,
            orig_addr: &ORIG_LOADLIBRARYW,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "LoadLibraryA",
            ordinal: 0,
            hook_addr: hooked_loadlibrarya as *const () as usize,
            orig_addr: &ORIG_LOADLIBRARYA,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "LoadLibraryExW",
            ordinal: 0,
            hook_addr: hooked_loadlibraryexw as *const () as usize,
            orig_addr: &ORIG_LOADLIBRARYEXW,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "LoadLibraryExA",
            ordinal: 0,
            hook_addr: hooked_loadlibraryexa as *const () as usize,
            orig_addr: &ORIG_LOADLIBRARYEXA,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "CreateProcessW",
            ordinal: 0,
            hook_addr: hooked_createprocessw as *const () as usize,
            orig_addr: &ORIG_CREATEPROCESSW,
        },
        HookDef {
            dll_name: "kernel32.dll",
            func_name: "CreateProcessA",
            ordinal: 0,
            hook_addr: hooked_createprocessa as *const () as usize,
            orig_addr: &ORIG_CREATEPROCESSA,
        },
    ]
}

pub unsafe fn reapply_hooks() {
    let hooks = build_hooks();
    iat::hook_all_loaded_modules(&hooks);
}

pub unsafe fn init_original_pointers() {
    let ws2 = GetModuleHandleA(b"ws2_32.dll\0".as_ptr());
    if !ws2.is_null() {
        if let Some(p) = GetProcAddress(ws2, b"connect\0".as_ptr()) {
            ORIG_CONNECT.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"WSAConnect\0".as_ptr()) {
            ORIG_WSACONNECT.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"GetAddrInfoW\0".as_ptr()) {
            ORIG_GETADDRINFOW.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"getaddrinfo\0".as_ptr()) {
            ORIG_GETADDRINFO.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"sendto\0".as_ptr()) {
            ORIG_SENDTO.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"WSAIoctl\0".as_ptr()) {
            ORIG_WSAIOCTL.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"WSASend\0".as_ptr()) {
            ORIG_WSASEND.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"send\0".as_ptr()) {
            ORIG_SEND.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(ws2, b"closesocket\0".as_ptr()) {
            ORIG_CLOSESOCKET.store(p as usize, Ordering::Relaxed);
        }
    }

    let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if !k32.is_null() {
        if let Some(p) = GetProcAddress(k32, b"GetProcAddress\0".as_ptr()) {
            ORIG_GETPROCADDRESS.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr()) {
            ORIG_LOADLIBRARYW.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(k32, b"LoadLibraryA\0".as_ptr()) {
            ORIG_LOADLIBRARYA.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(k32, b"LoadLibraryExW\0".as_ptr()) {
            ORIG_LOADLIBRARYEXW.store(p as usize, Ordering::Relaxed);
        }
        if let Some(p) = GetProcAddress(k32, b"LoadLibraryExA\0".as_ptr()) {
            ORIG_LOADLIBRARYEXA.store(p as usize, Ordering::Relaxed);
        }
        let kb = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
        if !kb.is_null() {
            if let Some(p) = GetProcAddress(kb, b"CreateProcessW\0".as_ptr()) {
                ORIG_CREATEPROCESSW.store(p as usize, Ordering::Relaxed);
            }
            if let Some(p) = GetProcAddress(kb, b"CreateProcessA\0".as_ptr()) {
                ORIG_CREATEPROCESSA.store(p as usize, Ordering::Relaxed);
            }
        }
        if ORIG_CREATEPROCESSW.load(Ordering::Relaxed) == 0 {
            if let Some(p) = GetProcAddress(k32, b"CreateProcessW\0".as_ptr()) {
                ORIG_CREATEPROCESSW.store(p as usize, Ordering::Relaxed);
            }
            if let Some(p) = GetProcAddress(k32, b"CreateProcessA\0".as_ptr()) {
                ORIG_CREATEPROCESSA.store(p as usize, Ordering::Relaxed);
            }
        }
    }
}

#[repr(C)]
pub struct WsaBuf {
    pub len: u32,
    pub buf: *mut u8,
}

struct PendingFrame {
    frame: Vec<u8>,
    timestamp: std::time::Instant,
}

static PENDING_CONNECT_FRAMES: std::sync::Mutex<Option<std::collections::HashMap<SOCKET, PendingFrame>>> =
    std::sync::Mutex::new(None);

fn store_pending_frame(s: SOCKET, frame: Vec<u8>) {
    if let Ok(mut guard) = PENDING_CONNECT_FRAMES.lock() {
        let map = guard.get_or_insert_with(std::collections::HashMap::new);
        let now = std::time::Instant::now();
        map.retain(|_, v| now.duration_since(v.timestamp).as_secs() < 30);
        map.insert(s, PendingFrame { frame, timestamp: now });
    }
}

fn take_pending_frame(s: SOCKET) -> Option<Vec<u8>> {
    if let Ok(mut guard) = PENDING_CONNECT_FRAMES.lock() {
        if let Some(map) = guard.as_mut() {
            if let Some(entry) = map.remove(&s) {
                if entry.timestamp.elapsed().as_secs() < 30 {
                    return Some(entry.frame);
                }
            }
        }
    }
    None
}

fn remove_pending_frame(s: SOCKET) {
    if let Ok(mut guard) = PENDING_CONNECT_FRAMES.lock() {
        if let Some(map) = guard.as_mut() {
            map.remove(&s);
        }
    }
}

unsafe fn get_socket_type(s: SOCKET) -> Option<i32> {
    let mut sock_type: i32 = 0;
    let mut optlen = std::mem::size_of::<i32>() as i32;
    let ret = getsockopt(
        s,
        SOL_SOCKET,
        SO_TYPE,
        &mut sock_type as *mut _ as *mut u8,
        &mut optlen,
    );
    if ret == 0 {
        Some(sock_type)
    } else {
        None
    }
}

unsafe fn get_connected_peer_port(s: SOCKET) -> Option<u16> {
    let mut buf = [0u8; 128];
    let mut len = buf.len() as i32;
    let ret = getpeername(s, buf.as_mut_ptr() as *mut SOCKADDR, &mut len);
    if ret == 0 && len >= std::mem::size_of::<SOCKADDR>() as i32 {
        let sa = buf.as_ptr() as *const SOCKADDR;
        let family = (*sa).sa_family;
        if family == AF_INET && len >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
            let sin = buf.as_ptr() as *const SOCKADDR_IN;
            return Some(u16::from_be((*sin).sin_port));
        } else if family == AF_INET6 && len >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
            let sin6 = buf.as_ptr() as *const SOCKADDR_IN6;
            return Some(u16::from_be((*sin6).sin6_port));
        }
    }
    None
}

unsafe fn check_udp_security_block(port: u16) -> bool {
    // 阻断 QUIC (UDP/443)
    if port == 443 {
        WSASetLastError(WSAECONNREFUSED);
        return true;
    }
    // 严格防泄漏模式阻断 UDP/53 DNS
    if port == 53 && STRICT_DNS.load(Ordering::Relaxed) {
        WSASetLastError(WSAECONNREFUSED);
        return true;
    }
    false
}

const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC8000006;
const WSAID_CONNECTEX_BYTES: [u8; 16] = [
    0xb9, 0x07, 0xa2, 0x25,
    0xf3, 0xdd,
    0x60, 0x46,
    0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e,
];

pub unsafe extern "system" fn hooked_wsapioctl(
    s: SOCKET,
    dw_io_control_code: u32,
    lpv_in_buffer: *mut c_void,
    cb_in_buffer: u32,
    lpv_out_buffer: *mut c_void,
    cb_out_buffer: u32,
    lpcb_bytes_returned: *mut u32,
    lp_overlapped: *mut c_void,
    lp_completion_routine: *mut c_void,
) -> i32 {
    let orig_fn = ORIG_WSAIOCTL.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return SOCKET_ERROR;
    }
    let orig_func: unsafe extern "system" fn(
        SOCKET, u32, *mut c_void, u32, *mut c_void, u32, *mut u32, *mut c_void, *mut c_void,
    ) -> i32 = std::mem::transmute(orig_fn);

    if dw_io_control_code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && cb_in_buffer >= 16
        && !lpv_in_buffer.is_null()
        && !lpv_out_buffer.is_null()
        && cb_out_buffer >= std::mem::size_of::<usize>() as u32
    {
        let guid_bytes = std::slice::from_raw_parts(lpv_in_buffer as *const u8, 16);
        if guid_bytes == WSAID_CONNECTEX_BYTES {
            crate::hook_log("WSAIoctl: 成功捕获 ConnectEx 扩展函数指针查询请求");
            let res = orig_func(
                s,
                dw_io_control_code,
                lpv_in_buffer,
                cb_in_buffer,
                lpv_out_buffer,
                cb_out_buffer,
                lpcb_bytes_returned,
                lp_overlapped,
                lp_completion_routine,
            );
            if res == 0 {
                let real_fn = *(lpv_out_buffer as *const usize);
                if real_fn != 0 && real_fn != hooked_connectex as *const () as usize {
                    ORIG_CONNECTEX.store(real_fn, Ordering::Relaxed);
                }
                *(lpv_out_buffer as *mut usize) = hooked_connectex as *const () as usize;
                return 0;
            }
            return res;
        }
    }

    orig_func(
        s,
        dw_io_control_code,
        lpv_in_buffer,
        cb_in_buffer,
        lpv_out_buffer,
        cb_out_buffer,
        lpcb_bytes_returned,
        lp_overlapped,
        lp_completion_routine,
    )
}

pub unsafe extern "system" fn hooked_connectex(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    lp_send_buffer: *const c_void,
    dw_send_data_length: u32,
    lpdw_bytes_sent: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32 {
    let orig_fn = ORIG_CONNECTEX.load(Ordering::Relaxed);
    if orig_fn == 0 || name.is_null() || namelen < std::mem::size_of::<SOCKADDR_IN>() as i32 {
        if orig_fn != 0 {
            let func: unsafe extern "system" fn(
                SOCKET, *const SOCKADDR, i32, *const c_void, u32, *mut u32, *mut c_void,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(
                s, name, namelen, lp_send_buffer, dw_send_data_length, lpdw_bytes_sent, lp_overlapped,
            );
        }
        return 0;
    }

    let orig_func: unsafe extern "system" fn(
        SOCKET, *const SOCKADDR, i32, *const c_void, u32, *mut u32, *mut c_void,
    ) -> i32 = std::mem::transmute(orig_fn);

    let family = (*name).sa_family;
    let relay_port = RELAY_PORT.load(Ordering::Relaxed);

    let hook_target = if family == AF_INET {
        let sin = &*(name as *const SOCKADDR_IN);
        let port = u16::from_be(sin.sin_port);
        let ip = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
        crate::hook_log(&format!("ConnectEx: IPv4 {}:{}, relay_port: {}", ip, port, relay_port));

        if ip.is_loopback() {
            return orig_func(
                s, name, namelen, lp_send_buffer, dw_send_data_length, lpdw_bytes_sent, lp_overlapped,
            );
        }

        if fakeip::is_fake_ip(&ip) {
            if let Some(domain) = fakeip::lookup_domain_by_ip(&ip) {
                HookTarget::Domain(domain, port)
            } else {
                HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
        } else {
            HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
    } else if family == AF_INET6 && namelen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
        let sin6 = &*(name as *const SOCKADDR_IN6);
        let port = u16::from_be(sin6.sin6_port);
        let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
        if ip.is_loopback() {
            return orig_func(
                s, name, namelen, lp_send_buffer, dw_send_data_length, lpdw_bytes_sent, lp_overlapped,
            );
        }
        HookTarget::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        return orig_func(
            s, name, namelen, lp_send_buffer, dw_send_data_length, lpdw_bytes_sent, lp_overlapped,
        );
    };

    let mut frame = hook_target.encode();
    if !lp_send_buffer.is_null() && dw_send_data_length > 0 {
        let initial_data = std::slice::from_raw_parts(lp_send_buffer as *const u8, dw_send_data_length as usize);
        frame.extend_from_slice(initial_data);
        if !lpdw_bytes_sent.is_null() {
            *lpdw_bytes_sent = dw_send_data_length;
        }
        store_pending_frame(s, frame);

        let mut relay_sin: SOCKADDR_IN = std::mem::zeroed();
        relay_sin.sin_family = AF_INET;
        relay_sin.sin_port = relay_port.to_be();
        relay_sin.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);

        return orig_func(
            s,
            &relay_sin as *const _ as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            lp_overlapped,
        );
    }

    store_pending_frame(s, frame);

    let mut relay_sin: SOCKADDR_IN = std::mem::zeroed();
    relay_sin.sin_family = AF_INET;
    relay_sin.sin_port = relay_port.to_be();
    relay_sin.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    orig_func(
        s,
        &relay_sin as *const _ as *const SOCKADDR,
        std::mem::size_of::<SOCKADDR_IN>() as i32,
        lp_send_buffer,
        dw_send_data_length,
        lpdw_bytes_sent,
        lp_overlapped,
    )
}

pub unsafe extern "system" fn hooked_wsasend(
    s: SOCKET,
    lp_buffers: *const WsaBuf,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    lp_overlapped: *mut c_void,
    lp_completion_routine: *mut c_void,
) -> i32 {
    if let Some(frame) = take_pending_frame(s) {
        crate::hook_log(&format!("WSASend: 首次发送前注入 {} 字节代理握手帧", frame.len()));
        let _ = send(s, frame.as_ptr(), frame.len() as i32, 0);
    }

    let orig_fn = ORIG_WSASEND.load(Ordering::Relaxed);
    if orig_fn != 0 {
        let orig_func: unsafe extern "system" fn(
            SOCKET, *const WsaBuf, u32, *mut u32, u32, *mut c_void, *mut c_void,
        ) -> i32 = std::mem::transmute(orig_fn);
        return orig_func(
            s,
            lp_buffers,
            dw_buffer_count,
            lp_number_of_bytes_sent,
            dw_flags,
            lp_overlapped,
            lp_completion_routine,
        );
    }
    SOCKET_ERROR
}

pub unsafe extern "system" fn hooked_send(
    s: SOCKET,
    buf: *const c_char,
    len: i32,
    flags: i32,
) -> i32 {
    if let Some(frame) = take_pending_frame(s) {
        crate::hook_log(&format!("send: 首次发送前注入 {} 字节代理握手帧", frame.len()));
        let _ = send(s, frame.as_ptr(), frame.len() as i32, 0);
    }

    let orig_fn = ORIG_SEND.load(Ordering::Relaxed);
    if orig_fn != 0 {
        let orig_func: unsafe extern "system" fn(SOCKET, *const c_char, i32, i32) -> i32 =
            std::mem::transmute(orig_fn);
        return orig_func(s, buf, len, flags);
    }
    SOCKET_ERROR
}

pub unsafe extern "system" fn hooked_closesocket(s: SOCKET) -> i32 {
    remove_pending_frame(s);
    let orig_fn = ORIG_CLOSESOCKET.load(Ordering::Relaxed);
    if orig_fn != 0 {
        let orig_func: unsafe extern "system" fn(SOCKET) -> i32 = std::mem::transmute(orig_fn);
        return orig_func(s);
    }
    0
}

pub unsafe extern "system" fn hooked_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
) -> i32 {
    let orig_fn = ORIG_CONNECT.load(Ordering::Relaxed);
    if orig_fn == 0 || name.is_null() || namelen < std::mem::size_of::<SOCKADDR_IN>() as i32 {
        if orig_fn != 0 {
            let func: unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32 =
                std::mem::transmute(orig_fn);
            return func(s, name, namelen);
        }
        return SOCKET_ERROR;
    }

    let orig_func: unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32 =
        std::mem::transmute(orig_fn);

    let family = (*name).sa_family;

    // 针对 UDP 套接字调用 connect 的情况处理 (SOCK_DGRAM)
    if let Some(sock_type) = get_socket_type(s) {
        if sock_type == SOCK_DGRAM {
            let target_port = if family == AF_INET && namelen >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
                let sin = &*(name as *const SOCKADDR_IN);
                Some(u16::from_be(sin.sin_port))
            } else if family == AF_INET6 && namelen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
                let sin6 = &*(name as *const SOCKADDR_IN6);
                Some(u16::from_be(sin6.sin6_port))
            } else {
                None
            };
            if let Some(port) = target_port {
                if check_udp_security_block(port) {
                    return SOCKET_ERROR;
                }
            }
            // 普通 UDP 连接放行至操作系统原始接口，严禁重定向至 TCP 中继端口
            return orig_func(s, name, namelen);
        }
    }

    let relay_port = RELAY_PORT.load(Ordering::Relaxed);

    let hook_target = if family == AF_INET {
        let sin = &*(name as *const SOCKADDR_IN);
        let port = u16::from_be(sin.sin_port);
        let ip = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
        crate::hook_log(&format!("connect: IPv4 {}:{}, relay_port: {}", ip, port, relay_port));

        // 环回直连白名单：防止重定向自身中继服务陷入死循环
        if ip.is_loopback() {
            return orig_func(s, name, namelen);
        }

        if fakeip::is_fake_ip(&ip) {
            if let Some(domain) = fakeip::lookup_domain_by_ip(&ip) {
                HookTarget::Domain(domain, port)
            } else {
                HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
        } else {
            HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
    } else if family == AF_INET6 && namelen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
        let sin6 = &*(name as *const SOCKADDR_IN6);
        let port = u16::from_be(sin6.sin6_port);
        let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
        if ip.is_loopback() {
            return orig_func(s, name, namelen);
        }
        HookTarget::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        return orig_func(s, name, namelen);
    };

    // 清除该套接字句柄可能残留的历史暂存帧，防止句柄复用引发串线
    remove_pending_frame(s);

    // 组装本地透明中继地址 127.0.0.1:<relay_port>
    let mut relay_sin: SOCKADDR_IN = std::mem::zeroed();
    relay_sin.sin_family = AF_INET;
    relay_sin.sin_port = relay_port.to_be();
    relay_sin.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let frame = hook_target.encode();

    let connect_res = orig_func(
        s,
        &relay_sin as *const _ as *const SOCKADDR,
        std::mem::size_of::<SOCKADDR_IN>() as i32,
    );

    if connect_res == 0 {
        let sent = send(s, frame.as_ptr(), frame.len() as i32, 0);
        if sent != frame.len() as i32 {
            let remaining = if sent > 0 && (sent as usize) < frame.len() {
                frame[sent as usize..].to_vec()
            } else {
                frame
            };
            store_pending_frame(s, remaining);
        }
        0
    } else {
        let err = WSAGetLastError();
        if err == WSAEWOULDBLOCK {
            // 非阻塞套接字连接进行中：严禁同步阻塞 select，立即暂存握手帧
            store_pending_frame(s, frame);
        }
        WSASetLastError(err);
        connect_res
    }
}

pub unsafe extern "system" fn hooked_wsaconnect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    caller_data: *mut c_void,
    callee_data: *mut c_void,
    sqos: *mut c_void,
    gqos: *mut c_void,
) -> i32 {
    let orig_fn = ORIG_WSACONNECT.load(Ordering::Relaxed);
    if orig_fn == 0 || name.is_null() || namelen < std::mem::size_of::<SOCKADDR_IN>() as i32 {
        if orig_fn != 0 {
            let func: unsafe extern "system" fn(
                SOCKET,
                *const SOCKADDR,
                i32,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(s, name, namelen, caller_data, callee_data, sqos, gqos);
        }
        return SOCKET_ERROR;
    }

    let orig_func: unsafe extern "system" fn(
        SOCKET,
        *const SOCKADDR,
        i32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    ) -> i32 = std::mem::transmute(orig_fn);

    let family = (*name).sa_family;

    // 针对 UDP 套接字调用 WSAConnect 的情况处理 (SOCK_DGRAM)
    if let Some(sock_type) = get_socket_type(s) {
        if sock_type == SOCK_DGRAM {
            let target_port = if family == AF_INET && namelen >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
                let sin = &*(name as *const SOCKADDR_IN);
                Some(u16::from_be(sin.sin_port))
            } else if family == AF_INET6 && namelen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
                let sin6 = &*(name as *const SOCKADDR_IN6);
                Some(u16::from_be(sin6.sin6_port))
            } else {
                None
            };
            if let Some(port) = target_port {
                if check_udp_security_block(port) {
                    return SOCKET_ERROR;
                }
            }
            return orig_func(s, name, namelen, caller_data, callee_data, sqos, gqos);
        }
    }

    let relay_port = RELAY_PORT.load(Ordering::Relaxed);

    let hook_target = if family == AF_INET {
        let sin = &*(name as *const SOCKADDR_IN);
        let port = u16::from_be(sin.sin_port);
        let ip = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
        crate::hook_log(&format!("WSAConnect: IPv4 {}:{}, relay_port: {}", ip, port, relay_port));

        if ip.is_loopback() {
            return orig_func(s, name, namelen, caller_data, callee_data, sqos, gqos);
        }

        if fakeip::is_fake_ip(&ip) {
            if let Some(domain) = fakeip::lookup_domain_by_ip(&ip) {
                HookTarget::Domain(domain, port)
            } else {
                HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
        } else {
            HookTarget::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
    } else if family == AF_INET6 && namelen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
        let sin6 = &*(name as *const SOCKADDR_IN6);
        let port = u16::from_be(sin6.sin6_port);
        let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
        if ip.is_loopback() {
            return orig_func(s, name, namelen, caller_data, callee_data, sqos, gqos);
        }
        HookTarget::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        return orig_func(s, name, namelen, caller_data, callee_data, sqos, gqos);
    };

    remove_pending_frame(s);

    let mut relay_sin: SOCKADDR_IN = std::mem::zeroed();
    relay_sin.sin_family = AF_INET;
    relay_sin.sin_port = relay_port.to_be();
    relay_sin.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let frame = hook_target.encode();

    let connect_res = orig_func(
        s,
        &relay_sin as *const _ as *const SOCKADDR,
        std::mem::size_of::<SOCKADDR_IN>() as i32,
        caller_data,
        callee_data,
        sqos,
        gqos,
    );

    if connect_res == 0 {
        let sent = send(s, frame.as_ptr(), frame.len() as i32, 0);
        if sent != frame.len() as i32 {
            let remaining = if sent > 0 && (sent as usize) < frame.len() {
                frame[sent as usize..].to_vec()
            } else {
                frame
            };
            store_pending_frame(s, remaining);
        }
        0
    } else {
        let err = WSAGetLastError();
        if err == WSAEWOULDBLOCK {
            store_pending_frame(s, frame);
        }
        WSASetLastError(err);
        connect_res
    }
}

pub unsafe extern "system" fn hooked_getaddrinfo(
    nodename: *const c_char,
    servicename: *const c_char,
    hints: *const c_void,
    result: *mut *mut AddrInfoA,
) -> i32 {
    let orig_fn = ORIG_GETADDRINFO.load(Ordering::Relaxed);
    if orig_fn == 0 || nodename.is_null() {
        if orig_fn != 0 {
            let func: unsafe extern "system" fn(
                *const c_char,
                *const c_char,
                *const c_void,
                *mut *mut AddrInfoA,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(nodename, servicename, hints, result);
        }
        return -1;
    }

    let domain = match std::ffi::CStr::from_ptr(nodename).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            if STRICT_DNS.load(Ordering::Relaxed) {
                WSASetLastError(11001);
                return 11001;
            }
            let func: unsafe extern "system" fn(
                *const c_char,
                *const c_char,
                *const c_void,
                *mut *mut AddrInfoA,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(nodename, servicename, hints, result);
        }
    };
    crate::hook_log(&format!("getaddrinfo: domain={}", domain));

    if domain.eq_ignore_ascii_case("localhost") || domain.parse::<std::net::IpAddr>().is_ok() {
        let func: unsafe extern "system" fn(
            *const c_char,
            *const c_char,
            *const c_void,
            *mut *mut AddrInfoA,
        ) -> i32 = std::mem::transmute(orig_fn);
        return func(nodename, servicename, hints, result);
    }

    if STRICT_DNS.load(Ordering::Relaxed) {
        let fake_ip = fakeip::get_or_allocate_fake_ip(&domain);
        let loopback = b"127.0.0.1\0".as_ptr() as *const c_char;
        let func: unsafe extern "system" fn(
            *const c_char,
            *const c_char,
            *const c_void,
            *mut *mut AddrInfoA,
        ) -> i32 = std::mem::transmute(orig_fn);
        let ret = func(loopback, servicename, hints, result);
        if ret == 0 && !result.is_null() && !(*result).is_null() {
            let mut curr = *result;
            while !curr.is_null() {
                if (*curr).ai_family == AF_INET as i32 && !(*curr).ai_addr.is_null() {
                    let sin = (*curr).ai_addr as *mut SOCKADDR_IN;
                    (*sin).sin_addr.S_un.S_addr = u32::from_ne_bytes(fake_ip.octets());
                }
                curr = (*curr).ai_next;
            }
        }
        return ret;
    }

    let func: unsafe extern "system" fn(
        *const c_char,
        *const c_char,
        *const c_void,
        *mut *mut AddrInfoA,
    ) -> i32 = std::mem::transmute(orig_fn);
    func(nodename, servicename, hints, result)
}

pub unsafe extern "system" fn hooked_getaddrinfow(
    nodename: *const u16,
    servicename: *const u16,
    hints: *const c_void,
    result: *mut *mut AddrInfoW,
) -> i32 {
    let orig_fn = ORIG_GETADDRINFOW.load(Ordering::Relaxed);
    if orig_fn == 0 || nodename.is_null() {
        if orig_fn != 0 {
            let func: unsafe extern "system" fn(
                *const u16,
                *const u16,
                *const c_void,
                *mut *mut AddrInfoW,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(nodename, servicename, hints, result);
        }
        return -1;
    }

    let mut len = 0;
    while len < 1024 && *nodename.add(len) != 0 {
        len += 1;
    }
    if len >= 1024 && STRICT_DNS.load(Ordering::Relaxed) {
        WSASetLastError(11001);
        return 11001;
    }
    let slice = std::slice::from_raw_parts(nodename, len);
    let domain = match String::from_utf16(slice) {
        Ok(s) => s,
        Err(_) => {
            if STRICT_DNS.load(Ordering::Relaxed) {
                WSASetLastError(11001);
                return 11001;
            }
            let func: unsafe extern "system" fn(
                *const u16,
                *const u16,
                *const c_void,
                *mut *mut AddrInfoW,
            ) -> i32 = std::mem::transmute(orig_fn);
            return func(nodename, servicename, hints, result);
        }
    };
    crate::hook_log(&format!("getaddrinfow: domain={}", domain));

    if domain.eq_ignore_ascii_case("localhost") || domain.parse::<std::net::IpAddr>().is_ok() {
        let func: unsafe extern "system" fn(
            *const u16,
            *const u16,
            *const c_void,
            *mut *mut AddrInfoW,
        ) -> i32 = std::mem::transmute(orig_fn);
        return func(nodename, servicename, hints, result);
    }

    if STRICT_DNS.load(Ordering::Relaxed) {
        let fake_ip = fakeip::get_or_allocate_fake_ip(&domain);
        let loopback_utf16: [u16; 10] = [
            '1' as u16, '2' as u16, '7' as u16, '.' as u16,
            '0' as u16, '.' as u16, '0' as u16, '.' as u16,
            '1' as u16, 0,
        ];
        let func: unsafe extern "system" fn(
            *const u16,
            *const u16,
            *const c_void,
            *mut *mut AddrInfoW,
        ) -> i32 = std::mem::transmute(orig_fn);
        let ret = func(loopback_utf16.as_ptr(), servicename, hints, result);
        if ret == 0 && !result.is_null() && !(*result).is_null() {
            let mut curr = *result;
            while !curr.is_null() {
                if (*curr).ai_family == AF_INET as i32 && !(*curr).ai_addr.is_null() {
                    let sin = (*curr).ai_addr as *mut SOCKADDR_IN;
                    (*sin).sin_addr.S_un.S_addr = u32::from_ne_bytes(fake_ip.octets());
                }
                curr = (*curr).ai_next;
            }
        }
        return ret;
    }

    let func: unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const c_void,
        *mut *mut AddrInfoW,
    ) -> i32 = std::mem::transmute(orig_fn);
    func(nodename, servicename, hints, result)
}

pub unsafe extern "system" fn hooked_sendto(
    s: SOCKET,
    buf: *const c_void,
    len: i32,
    flags: i32,
    to: *const SOCKADDR,
    tolen: i32,
) -> i32 {
    let orig_fn = ORIG_SENDTO.load(Ordering::Relaxed);
    let port = if !to.is_null() {
        let family = (*to).sa_family;
        if family == AF_INET && tolen >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
            let sin = &*(to as *const SOCKADDR_IN);
            Some(u16::from_be(sin.sin_port))
        } else if family == AF_INET6 && tolen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
            let sin6 = &*(to as *const SOCKADDR_IN6);
            Some(u16::from_be(sin6.sin6_port))
        } else {
            None
        }
    } else {
        get_connected_peer_port(s)
    };

    if let Some(port) = port {
        if check_udp_security_block(port) {
            return SOCKET_ERROR;
        }
    }

    if orig_fn != 0 {
        let func: unsafe extern "system" fn(
            SOCKET,
            *const c_void,
            i32,
            i32,
            *const SOCKADDR,
            i32,
        ) -> i32 = std::mem::transmute(orig_fn);
        func(s, buf, len, flags, to, tolen)
    } else {
        SOCKET_ERROR
    }
}

pub unsafe extern "system" fn hooked_wsasendto(
    s: SOCKET,
    lp_buffers: *const WsaBuf,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    lp_to: *const SOCKADDR,
    i_tolen: i32,
    lp_overlapped: *mut c_void,
    lp_completion_routine: *mut c_void,
) -> i32 {
    let orig_fn = ORIG_WSASENDTO.load(Ordering::Relaxed);
    let port = if !lp_to.is_null() {
        let family = (*lp_to).sa_family;
        if family == AF_INET && i_tolen >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
            let sin = &*(lp_to as *const SOCKADDR_IN);
            Some(u16::from_be(sin.sin_port))
        } else if family == AF_INET6 && i_tolen >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
            let sin6 = &*(lp_to as *const SOCKADDR_IN6);
            Some(u16::from_be(sin6.sin6_port))
        } else {
            None
        }
    } else {
        get_connected_peer_port(s)
    };

    if let Some(port) = port {
        if check_udp_security_block(port) {
            return SOCKET_ERROR;
        }
    }

    if orig_fn != 0 {
        let func: unsafe extern "system" fn(
            SOCKET,
            *const WsaBuf,
            u32,
            *mut u32,
            u32,
            *const SOCKADDR,
            i32,
            *mut c_void,
            *mut c_void,
        ) -> i32 = std::mem::transmute(orig_fn);
        func(
            s,
            lp_buffers,
            dw_buffer_count,
            lp_number_of_bytes_sent,
            dw_flags,
            lp_to,
            i_tolen,
            lp_overlapped,
            lp_completion_routine,
        )
    } else {
        SOCKET_ERROR
    }
}

pub unsafe extern "system" fn hooked_getprocaddress(
    module: HMODULE,
    proc_name: *const c_char,
) -> FARPROC {
    let orig_fn = ORIG_GETPROCADDRESS.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return None;
    }
    let orig_func: unsafe extern "system" fn(HMODULE, *const c_char) -> FARPROC =
        std::mem::transmute(orig_fn);

    if !proc_name.is_null() {
        if (proc_name as usize) > 0xFFFF {
            if let Ok(name) = std::ffi::CStr::from_ptr(proc_name).to_str() {
                match name {
                    "connect" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_connect as *const ()
                        ))
                    }
                    "WSAConnect" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsaconnect as *const ()
                        ))
                    }
                    "GetAddrInfoW" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_getaddrinfow as *const ()
                        ))
                    }
                    "getaddrinfo" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_getaddrinfo as *const ()
                        ))
                    }
                    "sendto" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_sendto as *const ()
                        ))
                    }
                    "WSASendTo" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsasendto as *const ()
                        ))
                    }
                    "LoadLibraryW" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_loadlibraryw as *const ()
                        ))
                    }
                    "LoadLibraryA" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_loadlibrarya as *const ()
                        ))
                    }
                    "LoadLibraryExW" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_loadlibraryexw as *const ()
                        ))
                    }
                    "LoadLibraryExA" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_loadlibraryexa as *const ()
                        ))
                    }
                    "CreateProcessW" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_createprocessw as *const ()
                        ))
                    }
                    "CreateProcessA" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_createprocessa as *const ()
                        ))
                    }
                    "WSAIoctl" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsapioctl as *const ()
                        ))
                    }
                    "ConnectEx" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_connectex as *const ()
                        ))
                    }
                    "WSASend" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsasend as *const ()
                        ))
                    }
                    "send" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_send as *const ()
                        ))
                    }
                    "closesocket" => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_closesocket as *const ()
                        ))
                    }
                    _ => {}
                }
            }
        } else {
            let ordinal = proc_name as usize;
            let ws2 = GetModuleHandleA(b"ws2_32.dll\0".as_ptr());
            if !ws2.is_null() && module == ws2 {
                match ordinal {
                    4 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_connect as *const ()
                        ))
                    }
                    46 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsaconnect as *const ()
                        ))
                    }
                    31 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_getaddrinfow as *const ()
                        ))
                    }
                    192 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_getaddrinfo as *const ()
                        ))
                    }
                    20 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_sendto as *const ()
                        ))
                    }
                    67 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsapioctl as *const ()
                        ))
                    }
                    72 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsasend as *const ()
                        ))
                    }
                    73 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_wsasendto as *const ()
                        ))
                    }
                    19 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_send as *const ()
                        ))
                    }
                    3 => {
                        return Some(std::mem::transmute::<
                            *const (),
                            unsafe extern "system" fn() -> isize,
                        >(
                            hooked_closesocket as *const ()
                        ))
                    }
                    _ => {}
                }
            }
        }
    }

    orig_func(module, proc_name)
}

pub unsafe extern "system" fn hooked_loadlibraryw(lib_filename: *const u16) -> HMODULE {
    let orig_fn = ORIG_LOADLIBRARYW.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return std::ptr::null_mut();
    }
    let orig_func: unsafe extern "system" fn(*const u16) -> HMODULE = std::mem::transmute(orig_fn);
    let hmod = orig_func(lib_filename);
    if !hmod.is_null() {
        reapply_hooks();
    }
    hmod
}

pub unsafe extern "system" fn hooked_loadlibrarya(lib_filename: *const c_char) -> HMODULE {
    let orig_fn = ORIG_LOADLIBRARYA.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return std::ptr::null_mut();
    }
    let orig_func: unsafe extern "system" fn(*const c_char) -> HMODULE =
        std::mem::transmute(orig_fn);
    let hmod = orig_func(lib_filename);
    if !hmod.is_null() {
        reapply_hooks();
    }
    hmod
}

pub unsafe extern "system" fn hooked_loadlibraryexw(
    lib_filename: *const u16,
    h_file: windows_sys::Win32::Foundation::HANDLE,
    dw_flags: u32,
) -> HMODULE {
    let orig_fn = ORIG_LOADLIBRARYEXW.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return std::ptr::null_mut();
    }
    let orig_func: unsafe extern "system" fn(
        *const u16,
        windows_sys::Win32::Foundation::HANDLE,
        u32,
    ) -> HMODULE = std::mem::transmute(orig_fn);
    let hmod = orig_func(lib_filename, h_file, dw_flags);
    if !hmod.is_null() {
        reapply_hooks();
    }
    hmod
}

pub unsafe extern "system" fn hooked_loadlibraryexa(
    lib_filename: *const c_char,
    h_file: windows_sys::Win32::Foundation::HANDLE,
    dw_flags: u32,
) -> HMODULE {
    let orig_fn = ORIG_LOADLIBRARYEXA.load(Ordering::Relaxed);
    if orig_fn == 0 {
        return std::ptr::null_mut();
    }
    let orig_func: unsafe extern "system" fn(
        *const c_char,
        windows_sys::Win32::Foundation::HANDLE,
        u32,
    ) -> HMODULE = std::mem::transmute(orig_fn);
    let hmod = orig_func(lib_filename, h_file, dw_flags);
    if !hmod.is_null() {
        reapply_hooks();
    }
    hmod
}

unsafe fn inject_child_process(h_process: windows_sys::Win32::Foundation::HANDLE) {
    if h_process.is_null() {
        crate::hook_log("inject_child_process: h_process is null");
        return;
    }

    // 1. 获取当前 shadow_hook 自身的绝对路径
    let mut dll_path_buf = [0u16; 1024];
    let our_base = crate::iat::OUR_MODULE_BASE.load(Ordering::Relaxed) as windows_sys::Win32::Foundation::HMODULE;
    let len = windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
        our_base,
        dll_path_buf.as_mut_ptr(),
        dll_path_buf.len() as u32,
    );
    if len == 0 {
        crate::hook_log("inject_child_process: GetModuleFileNameW failed");
        return;
    }

    let dll_path = String::from_utf16_lossy(&dll_path_buf[..len as usize]);
    crate::hook_log(&format!("inject_child_process: path = {}", dll_path));

    let dll_size_bytes = (len as usize + 1) * std::mem::size_of::<u16>();

    // 2. 在子进程空间中分配内存
    let remote_mem = windows_sys::Win32::System::Memory::VirtualAllocEx(
        h_process,
        std::ptr::null_mut(),
        dll_size_bytes,
        windows_sys::Win32::System::Memory::MEM_COMMIT | windows_sys::Win32::System::Memory::MEM_RESERVE,
        windows_sys::Win32::System::Memory::PAGE_READWRITE,
    );
    if remote_mem.is_null() {
        crate::hook_log(&format!("inject_child_process: VirtualAllocEx failed, err {}", windows_sys::Win32::Foundation::GetLastError()));
        return;
    }

    // 3. 写入 DLL 路径
    let mut written = 0;
    let ok = windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        h_process,
        remote_mem,
        dll_path_buf.as_ptr() as *const _,
        dll_size_bytes,
        &mut written,
    );
    if ok == 0 || written != dll_size_bytes {
        crate::hook_log(&format!("inject_child_process: WriteProcessMemory failed, err {}", windows_sys::Win32::Foundation::GetLastError()));
        windows_sys::Win32::System::Memory::VirtualFreeEx(
            h_process,
            remote_mem,
            0,
            windows_sys::Win32::System::Memory::MEM_RELEASE,
        );
        return;
    }

    // 4. 获取 kernel32!LoadLibraryW 真实函数地址
    let k32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if k32.is_null() {
        windows_sys::Win32::System::Memory::VirtualFreeEx(
            h_process,
            remote_mem,
            0,
            windows_sys::Win32::System::Memory::MEM_RELEASE,
        );
        return;
    }
    let load_lib = windows_sys::Win32::System::LibraryLoader::GetProcAddress(k32, b"LoadLibraryW\0".as_ptr());
    if load_lib.is_none() {
        windows_sys::Win32::System::Memory::VirtualFreeEx(
            h_process,
            remote_mem,
            0,
            windows_sys::Win32::System::Memory::MEM_RELEASE,
        );
        return;
    }

    // 5. 创建远程线程启动 LoadLibraryW 执行微运行时注入
    let routine: windows_sys::Win32::System::Threading::LPTHREAD_START_ROUTINE = std::mem::transmute(load_lib);
    let remote_thread = windows_sys::Win32::System::Threading::CreateRemoteThread(
        h_process,
        std::ptr::null_mut(),
        0,
        routine,
        remote_mem,
        0,
        std::ptr::null_mut(),
    );

    if remote_thread.is_null() {
        crate::hook_log(&format!("inject_child_process: CreateRemoteThread failed, err {}", windows_sys::Win32::Foundation::GetLastError()));
    } else {
        windows_sys::Win32::System::Threading::WaitForSingleObject(remote_thread, 5000);
        let mut exit_code = 0u32;
        windows_sys::Win32::System::Threading::GetExitCodeThread(remote_thread, &mut exit_code);
        crate::hook_log(&format!("inject_child_process: remote LoadLibraryW thread exit code: {:#x}", exit_code));
        windows_sys::Win32::Foundation::CloseHandle(remote_thread);
    }

    windows_sys::Win32::System::Memory::VirtualFreeEx(
        h_process,
        remote_mem,
        0,
        windows_sys::Win32::System::Memory::MEM_RELEASE,
    );
}

std::thread_local! {
    static IN_CREATE_PROCESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub unsafe extern "system" fn hooked_createprocessw(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *mut c_void,
    lp_thread_attributes: *mut c_void,
    b_inherit_handles: i32,
    dw_creation_flags: u32,
    lp_environment: *mut c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *mut c_void,
    lp_process_information: *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
) -> i32 {
    let orig = ORIG_CREATEPROCESSW.load(Ordering::Relaxed);
    if orig == 0 {
        return 0;
    }
    let orig_func: unsafe extern "system" fn(
        *const u16,
        *mut u16,
        *mut c_void,
        *mut c_void,
        i32,
        u32,
        *mut c_void,
        *const u16,
        *mut c_void,
        *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
    ) -> i32 = std::mem::transmute(orig);

    let in_call = IN_CREATE_PROCESS.with(|c| c.get());
    if in_call {
        return orig_func(
            lp_application_name,
            lp_command_line,
            lp_process_attributes,
            lp_thread_attributes,
            b_inherit_handles,
            dw_creation_flags,
            lp_environment,
            lp_current_directory,
            lp_startup_info,
            lp_process_information,
        );
    }

    IN_CREATE_PROCESS.with(|c| c.set(true));

    let was_suspended = (dw_creation_flags & windows_sys::Win32::System::Threading::CREATE_SUSPENDED) != 0;
    let forced_flags = dw_creation_flags | windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    let ret = orig_func(
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        b_inherit_handles,
        forced_flags,
        lp_environment,
        lp_current_directory,
        lp_startup_info,
        lp_process_information,
    );

    if ret != 0 && !lp_process_information.is_null() {
        let pi = &*lp_process_information;
        crate::hook_log(&format!("hooked_createprocessw: child PID {}", pi.dwProcessId));
        inject_child_process(pi.hProcess);
        if !was_suspended {
            windows_sys::Win32::System::Threading::ResumeThread(pi.hThread);
        }
    }

    IN_CREATE_PROCESS.with(|c| c.set(false));
    ret
}

pub unsafe extern "system" fn hooked_createprocessa(
    lp_application_name: *const c_char,
    lp_command_line: *mut c_char,
    lp_process_attributes: *mut c_void,
    lp_thread_attributes: *mut c_void,
    b_inherit_handles: i32,
    dw_creation_flags: u32,
    lp_environment: *mut c_void,
    lp_current_directory: *const c_char,
    lp_startup_info: *mut c_void,
    lp_process_information: *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
) -> i32 {
    let orig = ORIG_CREATEPROCESSA.load(Ordering::Relaxed);
    if orig == 0 {
        return 0;
    }
    let orig_func: unsafe extern "system" fn(
        *const c_char,
        *mut c_char,
        *mut c_void,
        *mut c_void,
        i32,
        u32,
        *mut c_void,
        *const c_char,
        *mut c_void,
        *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
    ) -> i32 = std::mem::transmute(orig);

    let in_call = IN_CREATE_PROCESS.with(|c| c.get());
    if in_call {
        return orig_func(
            lp_application_name,
            lp_command_line,
            lp_process_attributes,
            lp_thread_attributes,
            b_inherit_handles,
            dw_creation_flags,
            lp_environment,
            lp_current_directory,
            lp_startup_info,
            lp_process_information,
        );
    }

    IN_CREATE_PROCESS.with(|c| c.set(true));

    let was_suspended = (dw_creation_flags & windows_sys::Win32::System::Threading::CREATE_SUSPENDED) != 0;
    let forced_flags = dw_creation_flags | windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    let ret = orig_func(
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        b_inherit_handles,
        forced_flags,
        lp_environment,
        lp_current_directory,
        lp_startup_info,
        lp_process_information,
    );

    if ret != 0 && !lp_process_information.is_null() {
        let pi = &*lp_process_information;
        inject_child_process(pi.hProcess);
        if !was_suspended {
            windows_sys::Win32::System::Threading::ResumeThread(pi.hThread);
        }
    }

    IN_CREATE_PROCESS.with(|c| c.set(false));
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_security_block_quic_and_dns() {
        STRICT_DNS.store(true, Ordering::Relaxed);
        assert!(unsafe { check_udp_security_block(443) });
        assert!(unsafe { check_udp_security_block(53) });
        assert!(!unsafe { check_udp_security_block(80) });
        assert!(!unsafe { check_udp_security_block(8080) });

        STRICT_DNS.store(false, Ordering::Relaxed);
        assert!(unsafe { check_udp_security_block(443) });
        assert!(!unsafe { check_udp_security_block(53) });
        STRICT_DNS.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_pending_connect_frames_lifecycle() {
        let fake_socket: SOCKET = 12345;
        remove_pending_frame(fake_socket);
        assert!(take_pending_frame(fake_socket).is_none());

        let frame = vec![1, 2, 3, 4, 5];
        store_pending_frame(fake_socket, frame.clone());
        let retrieved = take_pending_frame(fake_socket);
        assert_eq!(retrieved, Some(frame));
        // 取出后队列中不再存在
        assert!(take_pending_frame(fake_socket).is_none());

        // 显式清理测试
        store_pending_frame(fake_socket, vec![9, 9, 9]);
        remove_pending_frame(fake_socket);
        assert!(take_pending_frame(fake_socket).is_none());
    }

    #[test]
    fn test_build_hooks_contains_wsasendto() {
        let hooks = unsafe { build_hooks() };
        assert_eq!(hooks.len(), 17);
        let has_sendto = hooks.iter().any(|h| h.func_name == "sendto" && h.ordinal == 20);
        let has_wsasendto = hooks.iter().any(|h| h.func_name == "WSASendTo" && h.ordinal == 73);
        assert!(has_sendto, "hooks must contain sendto");
        assert!(has_wsasendto, "hooks must contain WSASendTo");
    }
}

