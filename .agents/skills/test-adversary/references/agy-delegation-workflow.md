# agy CLI 委派模式工作流指南 (AGY Delegation Workflow)

本文档规范 `test-adversary` 与 Google Antigravity / `agy` CLI 环境联动的混合架构代码审查工作流。

---

## 1. 架构定位与委派机制

阿里开源代码审查工具 (Alibaba Open Code Review / OCR) 的核心思想是「确定性工程流水线 + LLM 推理引擎」的混合架构。在独立 CLI 场景下，OCR 通常依赖外部模型 API Key（如 OpenAI 或 Anthropic）；而在 Antigravity / `agy` 宿主环境中，`test-adversary` 通过委派模式（Delegation Mode）将 LLM 审查职责直接交由当前 Agent 会话完成，实现：

1. **零外部 API 依赖**：无需额外配置第三方大模型 Key 或网络代理。
2. **高性价比与抗干扰**：由确定性流水线先行剥离噪点文件、解析 Unified Diff、建立精确行号映射并命中规则候选集，大幅降低上下文 Token 消耗。
3. **行级精确定位**：所有审查反馈严格绑定在 Diff 实际产生的行号（`new_lineno`），彻底杜绝大模型行号幻觉（Line Drift）。

---

## 2. 委派执行流水线

```
[Git 变更 / Diff 文件]
       │
       ▼
[GitDiffExtractor] 提取统一差异 (Unified Diff)
       │
       ▼
[FileNoiseFilter] 过滤依赖锁、二进制、编译产物与测试假数据
       │
       ▼
[DiffParser] 解析 Hunks 并计算新增/修改行的绝对行号
       │
       ▼
[IndustrialRuleset] 确定性规则初筛 (NPE, SQLi, Concurrency, Leak)
       │
       ▼
[DelegationPackager] 生成审查上下文与针对 agy 的引导指令
       │
       ▼
[agy / Antigravity Agent] 执行上下文理解、候选核实与深度逻辑审查
       │
       ▼
[行级代码审查报告]
```

---

## 3. CLI 命令与调用方式

### 3.1 预检模式 (Preview)
在进行审查前，快速评估当前变更范围、过滤掉的噪点文件以及代码增删行数：
```bash
python skills/test-adversary/scripts/adversary_runner.py review --preview
```

### 3.2 委派审查模式 (Delegate Mode)
生成完整的委派上下文包并交由 Agent 审查：
```bash
# 审查工作区未提交变更 (workspace)
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate

# 审查已暂存变更 (staged)
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --staged

# 审查分支比对 (branch diff)
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --from main --to feature-branch

# 审查指定 commit
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --commit a1b2c3d

# 从已保存的 diff 文件审查
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --diff-file changes.patch

# 输出机器可读 JSON 包
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --json
```

### 3.3 确定性规则直接扫描 (Scan Mode)
仅运行确定性流水线与内置规则库，不触发 Agent 委派提示：
```bash
python skills/test-adversary/scripts/adversary_runner.py review --mode scan --strict
```

### 3.4 原生 OCR 桥接 (Native Mode)
若宿主机全局安装了阿里 `ocr` CLI，可通过 native 模式直接委托原生引擎执行：
```bash
python skills/test-adversary/scripts/adversary_runner.py review --mode native
```

---

## 4. Agent 委派审查执行准则

当 `agy` 接收到委派上下文时，必须遵循以下执行准则：

### 4.1 候选规则二次核实 (Verification)
确定性流水线命中的规则候选属于「高确信度预警」，Agent 需结合函数上下文进行排查：
- **确认违规 (Confirmed)**：确认存在漏洞或缺陷，保留该批注并提供针对性修复方案。
- **排除误报 (Dismissed)**：若上游已有防御性校验或类型系统保证安全，给出排除原因，不产生噪音批注。

### 4.2 深度语义审查 (Semantic Review)
不仅检查规则库覆盖的语法模式，重点关注：
- 业务逻辑边界与边界值遗漏（越界、边界符号错误）。
- 异步竞态条件与资源死锁。
- 权限校验与敏感信息泄露。
- 性能退化与 N+1 查询。

### 4.3 报告呈现格式规范
审查结果统一以表格与结构化批注输出，严禁使用 Emoji：

| 文件路径 | 行号 | 严重级别 | 规则 ID / 审查维度 | 缺陷描述与修复建议 |
|---|---|---|---|---|
| `src/auth.py` | 42 | HIGH | RULE-SEC-SQLI-001 | 使用 f-string 拼接动态 SQL 存在注入风险，改用参数化游标查询 |
| `pkg/pool.go` | 88 | HIGH | RULE-CONC-GO-001 | 未监听 ctx.Done() 可能导致协程泄漏，增加 defer 与 context 退出通道 |
