# test-adversary

面向代码与 Agent 资产的自动化对抗测试、测试断言有效性审计与混合架构代码审查工具（等效阿里 open-code-review）。

---

## 核心能力

| 能力模块 | 命令 | 说明 |
|---|---|---|
| **混合架构代码审查** | `review` | Git Diff 确定性解析、文件噪点过滤、工业级多语言规则初筛与 agy 委派模式（零 API Key 成本）。 |
| **静态对抗扫描** | `scan` | 静态挖掘反序列化、任意路径穿越、宽泛异常吞没与 Agent 资产越狱逃逸脆弱点。 |
| **测试断言审计** | `audit-test` | 基于 AST 语法树识别无断言测试（假绿灯）与恒真假断言（`assert True`）。 |
| **自动化测试执行** | `run` | 批量调度测试套件，提取失败轨迹与边界覆盖薄弱项。 |

---

## 技术架构

```
[Git 变更 / Diff 文件]
       │
       ▼
[GitDiffExtractor] 提取统一差异 (Unified Diff)
       │
       ▼
[FileNoiseFilter] 过滤依赖锁、二进制、编译产物
       │
       ▼
[DiffParser] 解析 Hunk 并计算确切新增/修改行号（防行号漂移）
       │
       ▼
[IndustrialRuleset] 多语言规则初筛 (Go NPE/协程泄漏, Java NPE/并发, TS XSS, SQLi, 资源未释放)
       │
       ▼
[DelegationPackager] 生成委派上下文与 agy 审查指令
       │
       ▼
[agy / Antigravity Agent] 深度语义推演与行级审查报告
```

---

## 快速上手 (CLI)

所有命令仅依赖 Python 3 标准库，零第三方外部包：

```bash
# 1. 预检当前代码变更与过滤噪点
python skills/test-adversary/scripts/adversary_runner.py review --preview

# 2. 委派模式审查当前工作区未提交变更 (agy 深度审查)
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate

# 3. 委派模式审查分支差异
python skills/test-adversary/scripts/adversary_runner.py review --mode delegate --from main --to HEAD

# 4. 纯确定性规则初筛与 CI 门禁阻断
python skills/test-adversary/scripts/adversary_runner.py review --mode scan --strict

# 5. 静态对抗弱点扫描
python skills/test-adversary/scripts/adversary_runner.py scan --dir ./src --mode code

# 6. 单测假阳性（假绿灯）审计
python skills/test-adversary/scripts/adversary_runner.py audit-test --dir ./tests --strict

# 7. 运行自动化测试
python skills/test-adversary/scripts/adversary_runner.py run --dir ./tests -v
```

---

## 退出码定义

| 退出码 | 含义 |
|---|---|
| `0` | 全部通过，未发现阻断级风险或测试全部通过 |
| `1` | 发现高危对抗弱点、假阳性断言、代码审查命中阻断规则或单测运行失败 |
| `2` | 命令行参数错误、目标路径不存在或 I/O 读取异常 |
