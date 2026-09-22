# ShadowProxy - Agent Governance

> 面向人类导览见 [README.md](./README.md)；通用元规则遵循全局规则。项目核心工程规范与底线规则定义于 [.specify/memory/constitution.md](./.specify/memory/constitution.md)。

## 专属 Skill 路由 (Specialized Skills)
- `test-adversary` ([.agent/skills/test-adversary](./.agent/skills/test-adversary/SKILL.md)): 代码对抗审查、单测假阳性审计与混合架构代码审查。当需要对项目进行红队安全检查、单测有效性审计或 PR 变更审查时触发。

<!-- RULES START -->
## 项目治理与核心原则（自动生成）
规则事实源： `.specify/memory/constitution.md`

### 核心架构与质量不变量：
#### 1. 架构分层与微运行时隔离 (Architectural Separation & Micro-Runtime in DLL)
- 注入至目标进程的 `shadow-hook` 动态库 MUST 保持极简微运行时设计，MUST NOT 在 `DllMain` 或目标进程内直接初始化重量级 Tokio 多线程异步运行时。
- 业务系统 MUST 严格按四层单向解耦构建：
- `shadow-hook`（Winsock C ABI Hook 动态库）
- `shadow-injector`（进程启动挂起、双架构 PE 判定与 DLL 注入器）
- `shadow-core`（Tokio 异步 SOCKS5/HTTP 传输与中继转发引擎）
- `shadow-cli` / `shadow-gui`（终端命令交互或桌面 UI 控制端）
- 展示层与注入层 MUST NOT 绕过核心中继引擎直接侵入底层 Hook 内存状态。
#### 2. 内存安全与 FFI 边界隔离 (Memory Safety & FFI Boundary Hygiene)
- 所有涉及 Winsock C 结构体（如 `sockaddr`, `addrinfoW`）及 Win32 API 裸指针的交互 MUST 严格限制在底层专用 `unsafe` 适配模块内。
- 暴露给上层的内部抽象接口 MUST 100% 为 Safe Rust，严禁裸指针向中继与业务模块扩散。
- 动态库编译配置 MUST 声明 `panic = "abort"`，严禁跨 FFI C-ABI 边界展开（unwind）Rust Panic。
#### 3. DNS 严格防泄漏与协议严苛约束 (DNS Anti-Leak & Protocol Strictness)
- 所有目标进程产生的 DNS 解析请求 MUST 经由安全代理通道解析（如 SOCKS5 域名代理解析或 DNS-over-TCP）。
- 在“严格防泄漏模式”下，当代理连接异常或解析失败时，系统 MUST 明确阻断或返回解析失败，MUST NOT 静默回退（fall back）到操作系统的普通明文 UDP/53 DNS 解析。
- QUIC (UDP/443) 流量在代理不支持原生 UDP 转发时 MUST 予以本地安全阻断，强制应用降级回退至 TCP 代理隧道。
#### 4. 双架构与平台兼容 (Dual-Architecture & Platform Compatibility)
- 注入器与 Hook 核心 MUST 原生支持 32 位（`i686-pc-windows-msvc`）与 64 位（`x86_64-pc-windows-msvc`）双架构目标程序。
- 注入器启动目标可执行文件时，MUST 首先解析目标 PE 头中的 Machine 字段；检测为 32 位程序时 MUST 调度对应 32 位专用注入模块。
- 针对 Windows UWP / WinStore 应用，系统 MUST 具备 Loopback 豁免（AppContainer 隔离规避）的自动化探测与处理能力。
#### 5. 测试先行与离线确定性保障 (Test-Backed Quality Gate)
- 协议解析（SOCKS5 握手、DoH/DNS 编码、UDP Associate 封包）与路由策略匹配模块 MUST 具备 100% 离线单元测试覆盖。
- 集成测试与中继模拟 MUST 采用 Mock 本地测试 Server，严禁在 CI/CD 单元测试中依赖外部公网连通性。
- 代码提交前 MUST 保证 `cargo check`、`cargo test` 与 `cargo clippy` 零警告通过。

### 工程卡点：
1. 方案推进前 MUST 对照项目核心规则自检。
2. 核心业务逻辑 MUST 保持自动化测试覆盖。
3. 规则更新 MUST 只落在边界标记内，不得覆盖自定义配置。
<!-- RULES END -->
