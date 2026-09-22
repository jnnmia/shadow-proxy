<!--
SYNC IMPACT REPORT
==================
Version change: 1.0.0 -> 1.1.0
Bump rationale: Project rebranded to ShadowProxy (shadow-core, shadow-hook, shadow-injector, shadow-cli, shadow-gui).

Principles defined:
  I.   Architectural Separation & Micro-Runtime in DLL
  II.  Memory Safety & FFI Boundary Hygiene
  III. DNS Anti-Leak & Protocol Strictness
  IV.  Dual-Architecture Compatibility (x86 & x64)
  V.   Test-Backed Quality Gate & Deterministic Mocking
-->

# ShadowProxy Constitution

## Overview
ShadowProxy 是一个基于纯 Rust 构建的 Windows 进程级透明代理与网络流量劫持转发系统。通过 DLL 注入与 Winsock API Hook，实现目标程序流量无感重定向到 SOCKS5/HTTP 代理。本文档确立项目的核心架构规范与不可违背的底线规则。

---

## Core Principles

### 1. 架构分层与微运行时隔离 (Architectural Separation & Micro-Runtime in DLL)
- 注入至目标进程的 `shadow-hook` 动态库 MUST 保持极简微运行时设计，MUST NOT 在 `DllMain` 或目标进程内直接初始化重量级 Tokio 多线程异步运行时。
- 业务系统 MUST 严格按四层单向解耦构建：
  1. `shadow-hook`（Winsock C ABI Hook 动态库）
  2. `shadow-injector`（进程启动挂起、双架构 PE 判定与 DLL 注入器）
  3. `shadow-core`（Tokio 异步 SOCKS5/HTTP 传输与中继转发引擎）
  4. `shadow-cli` / `shadow-gui`（终端命令交互或桌面 UI 控制端）
- 展示层与注入层 MUST NOT 绕过核心中继引擎直接侵入底层 Hook 内存状态。

*Rationale:* 注入环境处于第三方进程空间（如 Chrome、Node.js），重量级运行时或阻塞调用极易导致目标程序主线程卡死、崩溃或死锁。

### 2. 内存安全与 FFI 边界隔离 (Memory Safety & FFI Boundary Hygiene)
- 所有涉及 Winsock C 结构体（如 `sockaddr`, `addrinfoW`）及 Win32 API 裸指针的交互 MUST 严格限制在底层专用 `unsafe` 适配模块内。
- 暴露给上层的内部抽象接口 MUST 100% 为 Safe Rust，严禁裸指针向中继与业务模块扩散。
- 动态库编译配置 MUST 声明 `panic = "abort"`，严禁跨 FFI C-ABI 边界展开（unwind）Rust Panic。

*Rationale:* 杜绝跨语言边界的内存未定义行为（UB）与异常扩散，确保即便个别网络连接异常也不会拖垮宿主进程。

### 3. DNS 严格防泄漏与协议严苛约束 (DNS Anti-Leak & Protocol Strictness)
- 所有目标进程产生的 DNS 解析请求 MUST 经由安全代理通道解析（如 SOCKS5 域名代理解析或 DNS-over-TCP）。
- 在“严格防泄漏模式”下，当代理连接异常或解析失败时，系统 MUST 明确阻断或返回解析失败，MUST NOT 静默回退（fall back）到操作系统的普通明文 UDP/53 DNS 解析。
- QUIC (UDP/443) 流量在代理不支持原生 UDP 转发时 MUST 予以本地安全阻断，强制应用降级回退至 TCP 代理隧道。

*Rationale:* 保证网络流量劫持的 100% 安全性，防止浏览器或应用绕过代理导致真实 IP/域名泄露。

### 4. 双架构与平台兼容 (Dual-Architecture & Platform Compatibility)
- 注入器与 Hook 核心 MUST 原生支持 32 位（`i686-pc-windows-msvc`）与 64 位（`x86_64-pc-windows-msvc`）双架构目标程序。
- 注入器启动目标可执行文件时，MUST 首先解析目标 PE 头中的 Machine 字段；检测为 32 位程序时 MUST 调度对应 32 位专用注入模块。
- 针对 Windows UWP / WinStore 应用，系统 MUST 具备 Loopback 豁免（AppContainer 隔离规避）的自动化探测与处理能力。

*Rationale:* Windows 生产环境中大量存在 32 位遗留工具、游戏客户端及 UWP 沙盒应用，双架构与权限穿透是进程级透明代理的基础基线。

### 5. 测试先行与离线确定性保障 (Test-Backed Quality Gate)
- 协议解析（SOCKS5 握手、DoH/DNS 编码、UDP Associate 封包）与路由策略匹配模块 MUST 具备 100% 离线单元测试覆盖。
- 集成测试与中继模拟 MUST 采用 Mock 本地测试 Server，严禁在 CI/CD 单元测试中依赖外部公网连通性。
- 代码提交前 MUST 保证 `cargo check`、`cargo test` 与 `cargo clippy` 零警告通过。

*Rationale:* 网络中继协议细节繁多，必须依靠自动化与 Mock 确保每种异常状态（断线重连、协议拒绝）的健壮处理。

---

## Development Workflow & Checkpoints

开发流程建议按以下阶段推进：
1. **Spec 阶段**：明确需求交互边界，确定协议类型与支持的目标进程架构。
2. **Plan 阶段**：方案设计自检，对照微运行时、FFI 边界与 DNS 防泄漏原则核验。
3. **Tasks 阶段**：任务拆解至模块级，前置编写本地 Mock 与协议测试桩。
4. **Implement 阶段**：依序实现核心中继 -> 注入器 -> Hook DLL -> 交互端，零警告编译。
5. **Verify 阶段**：本地双架构进程启动测试与流量比对，验证无明文外泄。

---

## Rules Maintenance

1. **规则遵循**：新功能设计与代码实现需遵守既定规则。若现有规则与新场景冲突，应先评估并显式更新规则文档，不应私下绕过。
2. **版本管理 (SemVer)**：
   - **MAJOR**：删除、废弃或重大修改既有核心原则。
   - **MINOR**：新增原则、新增检查章节或扩充指导范围。
   - **PATCH**：文字勘误、格式微调、非语义性润色。
3. **变更记录**：修改核心原则时，需说明修改原因并在提交记录或文件顶部记录变更内容。
