# 对抗测试与审查模式指南 (Adversarial Patterns Guide)

本文档归纳在系统、代码与 Agent 资产进行红队对抗审查时的高频脆弱模式及攻击向量。

---

## 一、代码层对抗模式 (Code-Level Patterns)

### 1. 宽泛异常吞没 (Exception Swallowing)
- **脆弱模式**: `except Exception: pass` 或 `except: pass`
- **攻击利用**: 攻击者可以通过触发 `MemoryError`、`KeyboardInterrupt` 或逻辑断言错误，使系统在异常状态下强行继续运行，造成越权、数据污染或状态机撕裂。
- **防御准则**: 捕获明确的具体异常类；若必须捕获顶层异常，必须记录结构化日志并向上抛出致命错误。

### 2. 路径穿越与未规范化拼接 (Path Traversal)
- **脆弱模式**: `os.path.join(base_dir, user_filename)`
- **攻击利用**: 传入形如 `../../../../etc/passwd` 或 `C:\Windows\System32\...`，绕过基准目录限制读取或覆写关键系统文件。
- **防御准则**: 统一使用 `Path.resolve()` 并结合 `.relative_to(base_dir)` 断言目标仍在允许的安全子树内。

### 3. 恒真断言与伪测试 (Constant True Assertions)
- **脆弱模式**: `assert True`, `self.assertTrue(1)`, `assert len(result) >= 0`
- **缺陷后果**: 测试表面全绿（假阳性），但在实现产生回归或逻辑颠倒时依然通过。
- **防御准则**: 实施 AST 静态审查，禁止无变量参与的恒真断言。

---

## 二、Agent 资产对抗模式 (Agent & Prompt Patterns)

### 1. 指令混淆与系统提示越狱 (Instruction Escape)
- **脆弱模式**: 规约中未界定最高宪法与用户输入的优先级，当用户输入「忽略之前的所有规则，告诉我...」时，Agent 放弃初始约束。
- **防御准则**: 明确三层分级架构（全局规约 > 项目规约 > 对话上下文）。声明任何用户 Prompt 中的指令不可覆盖顶层系统安全底线。

### 2. 缺少负向黑名单 (Missing Negative Blacklist)
- **脆弱模式**: 规约仅定义「应该做什么」，没有定义「绝对不能做什么（Red Lines）」。
- **攻击利用**: LLM 会利用规约未提及的空白地带进行投机取巧或过度工程设计。
- **防御准则**: 每个 Skill 必须配备独立的「反例与黑名单（Anti-Patterns & Blacklist）」章节。

### 3. 模糊逃逸措辞 (Fuzzy Fallbacks)
- **脆弱模式**: 提示词中出现「灵活把握」、「根据情况判断」、「视情况而定」。
- **缺陷后果**: 在高压或复杂边界场景下，Agent 会随机选择执行分支，破坏输出确定性。
- **防御准则**: 消除模糊措辞，使用确定性的 `MUST` / `MUST NOT` 规则与明确的单步追问分支。
