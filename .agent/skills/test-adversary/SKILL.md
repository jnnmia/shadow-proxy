---
name: test-adversary
description: "用于代码与 Agent 资产的红队对抗审查、变异测试、断言有效性审计与混合架构代码审查（对齐阿里 open-code-review）。通过 CLI 运行确定性 Diff 流水线、多语言工业级缺陷初筛（NPE、并发安全、SQLi、资源泄漏）与 agy 委派审查。当用户提到测试、对抗审查、红队审计、代码审查、code review、ocr、单测有效性检查或 test-adversary 时使用。"
compatibility: "Python 3.8+（仅依赖标准库）"
agent_created: true
---

# test-adversary (测试与对抗审查红队工程师)

面向通用代码与 Agent 资产（Skill、规则、提示词）的自动化对抗测试、安全审查与行级代码审查工具。提供静态对抗弱点挖掘、测试断言有效性审计（识别假阳性测试）、输入边界压力探测，以及等效于阿里开源代码审查工具 (Alibaba Open Code Review / OCR) 的「确定性流水线 + agy 委派」混合架构代码审查能力。

---

## 能力边界

**能做**：
1. **静态对抗扫描**：检测代码中的未校验反序列化、任意文件路径穿越隐患、宽泛异常吞没、硬编码无条件通过断言，以及 Agent 资产中的系统指令逃逸点与 Prompt 注入脆弱点。
2. **测试质量与断言审计**：全面识别空断言、无断言测试（伪绿灯）、无效 Mock 与过度宽松断言（如 `assert len(x) >= 0`）。
3. **混合架构代码审查 (对齐阿里 OCR)**：
   - 提取 Git Diff（工作区修改、暂存区、分支比对、指定 commit 或统一 diff 文件）。
   - 自动过滤依赖锁文件、二进制与编译产物等噪点。
   - 解析 Unified Diff 并计算确切新旧行号映射，彻底杜绝大模型行号漂移。
   - 内置工业级多语言规则库（Go NPE/协程泄漏、Java 裸链式调用/并发集合、TS/JS 嵌套属性无保护/XSS、SQL 注入、资源未释放）。
   - 提供 agy 委派模式（Delegation Mode），将上下文直接移交当前 Agent 深度分析，零外部 API Key 成本。
4. **CLI 自动化测试执行**：批量运行工程测试套件，提取失败轨迹与边界覆盖薄弱项。

**不能做**：
1. 不替代业务单元测试的编写（本 Skill 专注寻找已有实现或测试的盲区与漏洞）。
2. 不发起任何外部网络攻击或运行期远程资源拉取。

---

## 触发条件

- **应当加载**：
  - 用户需要对代码、模块或系统开展对抗性测试、模糊边界测试或红队安全审计。
  - 用户需要排查单元测试是否存在「假绿灯」（假阳性、无效断言、伪 Mock）。
  - 用户需要进行精准行级代码审查（Code Review），特别是等效阿里 OCR 的工作流或希望由 agy 委派审查时。
  - 用户需要审计 Agent 资产（Skill 契约、系统规则、提示词）的鲁棒性与防绕过能力。
  - 用户明确指定调用 `test-adversary`。
- **不应当加载**：
  - 纯粹的新项目架构选型或规则脚手架生成（转由 `project-architect` 处理）。
  - 通用文档润色或博客撰写。

---

## 核心工作流 (Core Workflow)

```text
[阶段 1: 侦察与威胁建模] -> [阶段 2: 静态对抗扫描] -> [阶段 3: 断言与假阳性审计]
       │
       ├─> [阶段 4: 确定性流水线与 agy 委派审查] -> [行级审查报告与修复建议]
       │
       └─> [阶段 5: 边界对抗执行与自动化测试]
```

### 阶段 1：侦察与威胁建模 (Reconnaissance & Threat Modeling)
1. 识别目标对象类型：通用代码库（Go/Java/Python/TS 等）、Agent Skill 资产或 Prompt 规约。
2. 枚举输入边界与外部不可控源（CLI 参数、网络传入、文件系统读取、环境变量、用户自由文本）。

### 阶段 2：静态对抗扫描 (Static Adversarial Scanning)
通过 CLI 执行静态红队审计，检查已知对抗脆弱模式：
```bash
python scripts/adversary_runner.py scan --dir <项目路径> --mode all
```

### 阶段 3：测试有效性与断言审计 (Assertion & Test Audit)
排查项目现存单测的断言有效性，剔除虚假保护伞：
```bash
python scripts/adversary_runner.py audit-test --dir <测试目录路径>
```

### 阶段 4：确定性流水线与 agy 委派代码审查 (Code Review & Delegation)
对齐阿里 open-code-review 工业级混合审查架构：
1. **预检评估**：快速查看代码变动规模与噪点过滤情况：
   ```bash
   python scripts/adversary_runner.py review --preview
   ```
2. **委派审查模式 (Delegate Mode)**：由确定性流水线计算绝对行号并命中初筛规则，打包给 agy 深度推演：
   ```bash
   # 审查工作区变更
   python scripts/adversary_runner.py review --mode delegate
   # 审查已暂存变更
   python scripts/adversary_runner.py review --mode delegate --staged
   # 审查分支差异
   python scripts/adversary_runner.py review --mode delegate --from main --to feat-branch
   # 审查指定 commit
   python scripts/adversary_runner.py review --mode delegate --commit abc1234
   # 从 Unified Diff 文件审查
   python scripts/adversary_runner.py review --mode delegate --diff-file changes.patch
   ```
3. **确定性规则直接扫描 (Scan Mode)**：用于 CI 门禁或本地快速检查：
   ```bash
   python scripts/adversary_runner.py review --mode scan --strict
   ```

### 阶段 5：边界对抗执行与自动化测试 (Test Execution & Probing)
通过统一入口执行自动化测试，捕获未处理边界：
```bash
python scripts/adversary_runner.py run --dir <测试目录路径> --strict
```

---

## 命令行 CLI 工具参考

本 Skill 自带纯 Python 3 标准库 CLI 工具 `scripts/adversary_runner.py`：

```bash
# 1. 代码审查 (review: 确定性流水线 + agy 委派模式)
python scripts/adversary_runner.py review --preview
python scripts/adversary_runner.py review --mode delegate
python scripts/adversary_runner.py review --mode delegate --staged
python scripts/adversary_runner.py review --mode delegate --from main --to HEAD
python scripts/adversary_runner.py review --mode delegate --diff-file sample.patch --json
python scripts/adversary_runner.py review --mode scan --strict

# 2. 扫描对抗风险点 (scan)
python scripts/adversary_runner.py scan --dir ./src --mode code
python scripts/adversary_runner.py scan --dir ./skills --mode agent
python scripts/adversary_runner.py scan --dir . --mode all --json

# 3. 审计单测有效性 (audit-test)
python scripts/adversary_runner.py audit-test --dir ./tests
python scripts/adversary_runner.py audit-test --dir ./tests --strict

# 4. 运行测试并分析脆弱点 (run)
python scripts/adversary_runner.py run --dir ./tests -v
```

### 退出码契约 (Exit Codes)
| 退出码 | 含义 |
|---|---|
| `0` | 全部通过，未发现阻断级对抗风险或断言失效 |
| `1` | 发现高危对抗弱点、假阳性断言、代码审查命中阻断规则或单测运行失败 |
| `2` | 命令行参数错误、目标路径不存在或 I/O 读取异常 |

---

## 反例与黑名单 (Anti-Patterns & Blacklist)

1. **严禁编写只跑不测的伪测试**：禁止在测试函数中只调用业务代码却无有效 `assert`。
2. **严禁依赖过度宽泛断言**：如 `self.assertIsNotNone(result)` 替代对结构体核心字段精确值的校验。
3. **严禁生产代码吞没全部异常**：禁止使用 `except Exception: pass` 或空 `catch` 遮蔽底层致命错误。
4. **严禁在未规范化路径时拼接用户输入**：直接 `os.path.join(base, user_input)` 极易引发跨目录穿越。
5. **严禁审查产生漂移行号**：所有审查反馈必须严格依附于实际 Diff Hunk 的新旧行号，杜绝伪造行号。
6. **严禁在 Prompt 规则中仅写正向期待**：缺少「严禁行为（Blacklist）」的 Agent 规约极易被逆向越狱。

---

## 参考文档

| 文档 | 何时加载 |
|---|---|
| `references/industrial-ruleset.md` | 需要查阅多语言工业级审查规则定义（NPE、并发、注入、资源泄露等）时 |
| `references/agy-delegation-workflow.md` | 需要了解 agy CLI 委派模式执行细节与提示词协议时 |
| `references/adversarial-patterns.md` | 需要查阅常见代码注入、路径穿越及 Prompt 越狱对抗模式时 |
| `references/assertion-audit-guide.md` | 进行测试套件质量加固与假阳性识别时 |

---

## 契约自检 (Self-Check)

- [x] 目录名为小写 kebab-case，且与上方 `name: test-adversary` 逐字符一致。
- [x] `description` 明确说明能力边界、OCR 等效混合架构与 CLI 触发场景。
- [x] 核心实现纯 Python 3 标准库，无网络请求，跨平台 UTF-8/LF 确定性输出。
- [x] 路径计算防穿越，零硬编码敏感凭据。
- [x] 全文严格遵循零 Emoji 规范。
