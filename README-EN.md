# ShadowProxy

> Technical dashboard for humans. For agent governance, see [AGENTS.md](./AGENTS.md).

Process-level transparent proxy engine for Windows, rewritten in pure Rust. Uses user-mode Winsock C-ABI hooks and PE dynamic injection to redirect network traffic from designated processes and their child processes to a local async relay engine and upstream SOCKS5 proxies. No UAC elevation, no TUN/TAP driver, and no system-wide routing table alterations.

---

## Architecture & Tech Stack

| Crate | Path | Responsibility | Runtime Model |
|---|---|---|---|
| `shadow-hook` | `crates/shadow-hook` | Winsock C-ABI hooks, Fake-IP mapping, QUIC blocking | Micro-runtime (No async runtime, zero DllMain blocking) |
| `shadow-injector` | `crates/shadow-injector` | Dual-architecture PE detection, suspended process spawn, DLL injection | Safe/Unsafe boundary isolated Win32 abstraction |
| `shadow-core` | `crates/shadow-core` | SOCKS5 protocol codec, transparent relay listener, zero-copy relay | Tokio async event-driven engine |
| `shadow-cli` | `crates/shadow-cli` | CLI runner, architecture detection, DLL resolution, and process supervisor | Clap 4.5 terminal interface |
| `shadow-gui` | `crates/shadow-gui` | Native desktop console, drag-drop capture, process injection & live telemetry | Wry 0.57 / Tao 0.37 native WebView |

---

## Key Engineering Features

| Feature | Technical Implementation | Benefit |
|---|---|---|
| Micro-Runtime in DLL | DLL keeps only minimal C-ABI hook table; networking is delegated to host process | Eliminates DllMain async deadlocks and injection crashes |
| Strict DNS Anti-Leak | RFC 2544 Fake-IP (198.18.0.0/15) in-memory table + local UDP/53 blocking | Zero plaintext DNS leakage; 100% remote SOCKS5 resolution |
| QUIC Downgrade Blocking | Intercepts UDP/443 returning WSAECONNREFUSED | Forces browsers and modern apps to fall back cleanly to TCP proxy tunnels |
| Dual-Architecture Support | Automatic PE Machine parsing for x86 (0x014c) and x64 (0x8664) | Dispatches matching architecture-specific hook DLLs |
| Deterministic Offline Tests | Full Mock SOCKS5 test suites aligned with test-adversary audits | Zero warnings, zero test failures, zero false positive assertions |

---

## Getting Started

### Prerequisites
- Windows 10 / 11 (x86_64 or i686)
- Rust 1.82+ (`x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`)

### Build
```powershell
cargo build --workspace --release
```

### Usage
```powershell
# 1. Launch GUI directly via project script or binary
.\start-gui.bat
# (or run .\bin\shadow-gui.exe directly)

# 2. Launch target process under transparent proxy (CLI)
.\start-cli.bat --proxy 127.0.0.1:10808 --target C:\Windows\System32\curl.exe --args "https://api.ipify.org"

# 3. Or run as standalone transparent relay daemon
.\start-cli.bat --proxy 127.0.0.1:10808 --listen 127.0.0.1:19090
```

### Quality Verification
```powershell
# Run all workspace unit tests
cargo test --workspace

# Run Clippy strict check
cargo clippy --workspace --all-targets -- -D warnings

# Run test-adversary red team review
python .agent/skills/test-adversary/scripts/adversary_runner.py review --mode scan --strict
```

---

## License
This project is licensed under the [MIT License](./LICENSE).
