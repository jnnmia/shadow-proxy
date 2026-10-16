# ShadowProxy

[English](./README-EN.md) | [简体中文](./README.md)

ShadowProxy is a Windows process-level transparent proxy tool built in pure Rust. Using user-mode Winsock C-ABI interception and PE dynamic injection, it redirects TCP and DNS traffic from selected target processes and child processes to a local async relay and upstream SOCKS5 proxies.

Requires no administrator privileges, installs no virtual network card (TUN/TAP) drivers, and leaves system-wide network routing unchanged.

---

## Key Features

| Feature | Technical Implementation | Benefit |
|---|---|---|
| No UAC & No Drivers | User-mode Winsock C-ABI interception | No administrator prompts, no driver installation, zero global network impact |
| Micro-Runtime in DLL | Minimal C-ABI hook table in DLL; networking in host process | Eliminates DllMain deadlocks and target process crashes |
| Strict DNS Anti-Leak | RFC 2544 Fake-IP memory mapping + local UDP/53 interception | Zero plaintext DNS leakage; all lookups routed via SOCKS5 or DoT |
| QUIC Blocking | Intercepts UDP/443 and returns connection refused | Forces browsers and modern network stacks to fall back cleanly to TCP proxy tunnels |
| Dual-Architecture Support | Automatic PE Machine parsing (x86 / x64) | Automatically detects target architecture and dispatches 32-bit or 64-bit hook modules |
| Upstream Health Probe & Tri-State | Pre-flight SOCKS5 / HTTP CONNECT handshake + background heartbeat | Prevents false ONLINE illusion; auto-recovery upon sleep resume & graceful degradation |
| Process-Aware Routing Engine | Relay Frame Protocol v2 with PID & process name tags | Domain, CIDR, port range, and granular routing based on originating process name |
| Attach to Running & System Tray | ToolHelp32 snapshot enumeration + Shell_NotifyIconW | Dynamically inject into running processes and minimize seamlessly to native Win32 tray |

---

## Downloads

Download the latest version from [GitHub Releases](https://github.com/jnnmia/shadow-proxy/releases/latest):

| Package | Filename | Description |
|---|---|---|
| Installer | `ShadowProxy-Setup-v0.2.0.exe` | Standalone setup wizard; configures Desktop/Start Menu shortcuts and uninstaller |
| Portable | `ShadowProxy-v0.2.0-windows-portable.zip` | Standalone archive; extract and double-click `start-gui.bat` to run |

---

## Quick Start

### 1. GUI (Recommended)
- Run `start-gui.bat` (or use the installed desktop shortcut).
- Drag and drop any executable (`.exe`) or shortcut (`.lnk`) into the window.
- Enter your upstream SOCKS5 proxy address (e.g., `127.0.0.1:10808`) and launch.

### 2. Command Line (CLI)
```powershell
# Launch target program under transparent proxy (e.g. curl)
.\start-cli.bat --proxy 127.0.0.1:10808 --target C:\Windows\System32\curl.exe --args "https://api.ipify.org -v"

# Run as standalone transparent relay daemon
.\start-cli.bat --proxy 127.0.0.1:10808 --listen 127.0.0.1:19090
```

---

## AI Coding Assistants Setup (Antigravity & Codex)

### Use Cases

| Tool / Environment | Typical Pain Points | ShadowProxy Solution |
|---|---|---|
| Google Antigravity | Internal Electron, Python sidecars, and gRPC backends ignore system proxies | Injects into the host process and tracks entire child process trees |
| OpenAI Codex / Copilot | Language server sub-processes and CLI tools fail to respect env vars | Intercepts at the Winsock C-ABI layer without per-runtime config |
| Strict DNS & Network Isolation | Plaintext DNS queries trigger timeouts or leak target hostnames | RFC 2544 Fake-IP mapping with remote SOCKS5 DNS resolution |

### Step-by-Step Tutorial

- **1. Drag & Drop Injection via GUI (Recommended)**
  - Start `ShadowProxy` and ensure the status chip displays `ONLINE`.
  - Drag and drop your Antigravity shortcut (`.lnk`) or executable (`Antigravity.exe`) into the window.
  - Click "Launch with Proxy"; Antigravity and all spawned worker processes will immediately route through the relay.

- **2. Attach to Running Processes (Runtime Attach)**
  - If Antigravity, Cursor, or VSCode (with Codex extensions) is already running, switch to the "Processes" tab.
  - Filter for `Antigravity.exe` or `Code.exe` in the search box, then click "Attach" to intercept live network sockets.

- **3. Command Line Launch**
  ```powershell
  # Launch Antigravity under transparent proxy
  .\start-cli.bat --proxy 127.0.0.1:10808 --target "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe"

  # Launch editor with full child process tunneling
  .\start-cli.bat --proxy 127.0.0.1:10808 --target "C:\Program Files\Microsoft VS Code\Code.exe"
  ```

---

## Architecture

| Crate | Directory | Responsibility |
|---|---|---|
| `shadow-gui` | `crates/shadow-gui` | Desktop console using Wry/Tao native WebView; supports drag-drop and real-time telemetry |
| `shadow-cli` | `crates/shadow-cli` | Command-line runner using Clap 4.5; manages process launch, architecture dispatch, and supervision |
| `shadow-core` | `crates/shadow-core` | Core relay engine using Tokio async runtime; handles SOCKS5 tunneling and DNS-over-TCP |
| `shadow-injector` | `crates/shadow-injector` | Process injector; creates suspended target processes and injects hook DLL with safe Win32 abstractions |
| `shadow-hook` | `crates/shadow-hook` | Winsock C-ABI hooks; handles Fake-IP mapping, DNS interception, and QUIC blocking |

---

## Build from Source

### Prerequisites
- Windows 10 / 11 (x86_64 or i686)
- Rust 1.82+ (`x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`)
- Python 3.10+ (for release packaging scripts)

### Build Commands
```powershell
# Build workspace release binaries
cargo build --workspace --release

# Run unit tests
cargo test --workspace

# Package standalone installer and portable zip
.\package.bat
```

---

## License

This project is licensed under the [MIT License](./LICENSE).
