# ShadowProxy

[简体中文](./README.md) | [English](./README-EN.md)

ShadowProxy 是一款基于 Rust 开发的 Windows 进程级透明代理工具。通过用户态 Winsock C-ABI 拦截桩与 PE 动态注入技术，将指定进程及其子进程的网络流量直接导向本地透明中继与上游 SOCKS5 代理。

无需管理员权限，无需安装虚拟网卡（TUN/TAP）驱动，不修改系统全局网络与路由表设置。

---

## 核心特性

| 特性 | 技术实现 | 优势 |
|---|---|---|
| 免提权与免驱动 | 用户态 Winsock C-ABI 拦截 | 无需管理员提权弹窗，不安装驱动，不影响系统全局网络 |
| 微运行时架构 | Hook 动态库极简轻量，中继下沉至主进程 | 避免 DllMain 注入时的异步死锁与目标程序卡死崩溃 |
| 严格 DNS 防泄漏 | RFC 2544 Fake-IP 内存映射 + 本地 UDP/53 拦截 | 目标进程无明文 DNS 解析泄漏，强制远端 SOCKS5 或 DoT 解析 |
| QUIC 协议阻断 | 拦截目标程序 UDP/443 并返回连接拒绝 | 促使浏览器与现代网络应用平稳降级至 TCP 代理隧道 |
| 双架构自动识别 | PE 头 Machine 字段识别 x86 / x64 | 自动探测目标程序架构并调度对应 32 位或 64 位注入模块 |
| 上游探活与三态感知 | 前置 SOCKS5 / HTTP CONNECT 握手 + 心跳探活 | 杜绝上游未启动时的虚假在线假象，支持休眠唤醒自愈恢复与断线降级 |
| 进程识别分流引擎 | 中继帧协议 v2 (PID 与进程名标识) | 支持域名、IP-CIDR、端口范围及按发起进程名精细化分流 |
| 运行时附加与原生托盘 | Win32 ToolHelp32 快照 + Shell_NotifyIconW | 支持向运行中进程动态附加注入，最小化至系统托盘常驻后台 |

---

## 下载与安装

请前往 [GitHub Releases](https://github.com/jnnmia/shadow-proxy/releases/latest) 获取最新版本：

| 分发形态 | 文件名 | 说明 |
|---|---|---|
| 独立安装包 | `ShadowProxy-Setup-v0.2.1.exe` | 单文件安装程序，一键配置桌面与开始菜单快捷方式，支持系统标准卸载 |
| 免安装绿色包 | `ShadowProxy-v0.2.1-windows-portable.zip` | 解压即用，直接运行 `start-gui.bat` 即可启动 |

---

## 快速使用

### 1. 图形界面操作 (推荐)
- 双击运行 `start-gui.bat`（或从安装后的桌面快捷方式启动）。
- 将目标可执行文件（`.exe`）或快捷方式（`.lnk`）直接拖入主窗口。
- 填写上游 SOCKS5 代理地址（例如 `127.0.0.1:10808`），点击启动代理。

### 2. 命令行操作
```powershell
# 代理指定程序运行 (例如 curl)
.\start-cli.bat --proxy 127.0.0.1:10808 --target C:\Windows\System32\curl.exe --args "https://api.ipify.org -v"

# 作为独立透明中继后台服务运行
.\start-cli.bat --proxy 127.0.0.1:10808 --listen 127.0.0.1:19090
```

---

## AI 编程助手代理实践 (Antigravity & Codex)

### 适用场景

| 工具 / 场景 | 典型痛点 | ShadowProxy 解决方案 |
|---|---|---|
| Google Antigravity | 内部 Electron、Python 侧车与 gRPC 后台常忽略系统代理 | 注入主进程并自动穿透子进程树，强制所有网络通信走中继 |
| OpenAI Codex / Copilot | CLI 命令行工具、Node.js 运行时或特定语言插件连接超时 | 从 Winsock 底层捕获流量，无需针对不同语言单独配环境变量 |
| 严格网络与 DNS 审计 | 域名解析外泄导致连接阻断或凭据泄漏 | RFC 2544 Fake-IP 本地映射 + 远端 SOCKS5 域名解析，杜绝 DNS 泄漏 |

### 快速配置教程

- **1. 图形界面拖拽注入 (推荐)**
  - 启动 `ShadowProxy` 并确认状态显示为 `ONLINE`。
  - 将桌面上的 Antigravity 快捷方式（`.lnk`）或安装目录可执行文件（`Antigravity.exe`）拖入主界面，点击「启动并注入代理」。
  - 宿主程序及其派生的所有语言服务、扩展进程将自动纳入代理隧道。

- **2. 对已运行进程附加代理 (Runtime Attach)**
  - 若 Antigravity、Cursor 或 VSCode (含 Codex 插件) 已在运行，进入「进程列表」视口。
  - 在搜索框输入目标进程名（如 `Antigravity.exe` 或 `Code.exe`），点击「附加注入」即可实时捕获后续网络流。

- **3. 命令行静默启动**
  ```powershell
  # 代理启动 Antigravity
  .\start-cli.bat --proxy 127.0.0.1:10808 --target "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe"

  # 代理启动开发终端或编辑器
  .\start-cli.bat --proxy 127.0.0.1:10808 --target "C:\Program Files\Microsoft VS Code\Code.exe"
  ```

---

## 架构组成

| 模块 | 目录 | 职责与技术选型 |
|---|---|---|
| `shadow-gui` | `crates/shadow-gui` | 原生桌面控制台，基于 Wry/Tao 原生 WebView 构建，支持文件拖拽与实时流量看板 |
| `shadow-cli` | `crates/shadow-cli` | 命令行控制端，基于 Clap 4.5，负责目标探测、注入启动与生命周期守护 |
| `shadow-core` | `crates/shadow-core` | 核心网络中继引擎，基于 Tokio 异步运行时，实现 SOCKS5 转发与 DNS-over-TCP |
| `shadow-injector` | `crates/shadow-injector` | 进程注入器，挂起创建目标进程并注入 Hook 动态库，Safe/Unsafe 严格隔离 |
| `shadow-hook` | `crates/shadow-hook` | Winsock C-ABI 拦截桩，负责 Fake-IP 内存映射、DNS 与 QUIC 流量拦截 |

---

## 源码构建

### 环境要求
- Windows 10 / 11 (x86_64 或 i686)
- Rust 1.82+ (`x86_64-pc-windows-gnu` 或 `x86_64-pc-windows-msvc`)
- Python 3.10+ (用于运行打包与分发脚本)

### 编译与打包
```powershell
# 编译全工作区 Release 产物
cargo build --workspace --release

# 执行全工作区单元测试
cargo test --workspace

# 一键打包生成独立安装包与便携包
.\package.bat
```

---

## 开源协议

本项目采用 [MIT 许可证](./LICENSE)。
