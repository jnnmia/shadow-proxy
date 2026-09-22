# ShadowProxy

> 面向人类导览看板；面向 Agent 治理规约见 [AGENTS.md](./AGENTS.md)。

Windows 进程级透明代理引擎，基于 Rust 构建。通过用户态 Winsock C-ABI 拦截桩与 PE 动态注入技术，将指定进程及其子进程的 TCP/DNS 流量重定向至本地异步中继引擎与上游 SOCKS5 代理。无需配置管理员提权、无需安装 TUN/TAP 虚拟网卡驱动，不污染系统全局路由表。

---

## 架构与技术栈

| 模块 | 目录 | 职责与核心技术 | 运行时形态 |
|---|---|---|---|
| `shadow-hook` | `crates/shadow-hook` | Winsock C-ABI 拦截桩、Fake-IP 映射、QUIC 阻断 | 微运行时 (无异步运行时，无 DllMain 阻塞) |
| `shadow-injector` | `crates/shadow-injector` | 双架构 PE 判定、挂起创建 (CREATE_SUSPENDED)、远程线程注入 | 纯 Safe/Unsafe 边界隔离 Win32 抽象 |
| `shadow-core` | `crates/shadow-core` | SOCKS5 协议编解码、本地透明中继监听、双向流零拷贝 | Tokio 异步事件驱动引擎 |
| `shadow-cli` | `crates/shadow-cli` | 命令行启动器、自动探测架构、动态库路径解析与生命周期守护 | Clap 4.5 终端交互 |
| `shadow-gui` | `crates/shadow-gui` | 原生桌面控制台、文件拖拽捕获、注入管理与实时流量看板 | Wry 0.57 / Tao 0.37 原生 WebView |

---

## 核心工程特性

| 特性 | 技术实现 | 优势保障 |
|---|---|---|
| 微运行时隔离 | 动态库只保留极简 C-ABI Hook 表，网络中继下沉至独立主进程 | 彻底杜绝 DllMain 注入时的异步死锁与崩溃 |
| DNS 严格防泄漏 | RFC 2544 Fake-IP (198.18.0.0/15) 内存映射与本地 UDP/53 拦截 | 目标进程零明文域名泄露，100% 远端 SOCKS5 域名解析 |
| QUIC 降级阻断 | 拦截 UDP/443 并返回 WSAECONNREFUSED | 强制浏览器与现代应用自动平稳回退至 TCP 代理隧道 |
| 双架构兼容 | PE Machine 字段自动识别 x86 (0x014c) 与 x64 (0x8664) | 自动调度匹配目标架构的专用 Hook 模块 |
| 确定性离线测试 | 全套 Mock SOCKS5 测试服务与离线单元测试，对齐 test-adversary 审计 | 持续保障零警告、零失败与无假阳性断言 |

---

## 快速上手

### 环境要求
- Windows 10 / 11 (x86_64 或 i686)
- Rust 1.82+ (支持 `x86_64-pc-windows-gnu` 或 `x86_64-pc-windows-msvc`)

### 编译构建
```powershell
# 编译全工作区 Release 产物
cargo build --workspace --release
```

### 运行代理
```powershell
# 1. 直接双击或运行项目根目录脚本启动图形界面
.\start-gui.bat
# (或直接运行 .\bin\shadow-gui.exe)

# 2. 注入目标程序并启动透明代理 (命令行模式)
.\start-cli.bat --proxy 127.0.0.1:10808 --target C:\Windows\System32\curl.exe --args "https://api.ipify.org"

# 3. 或单独作为透明代理中继守护运行
.\start-cli.bat --proxy 127.0.0.1:10808 --listen 127.0.0.1:19090
```

### 运行质量验证
```powershell
# 执行全工作区单元测试
cargo test --workspace

# 执行 Clippy 严格静态检查
cargo clippy --workspace --all-targets -- -D warnings

# 执行 test-adversary 红队审计
python .agent/skills/test-adversary/scripts/adversary_runner.py review --mode scan --strict
```

---

## 协议与授权
本项目采用 [MIT 许可证](./LICENSE)。
