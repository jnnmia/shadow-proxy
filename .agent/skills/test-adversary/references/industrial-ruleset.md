# 多语言工业级代码审查规则库 (Industrial Ruleset)

本文档归纳对齐阿里开源代码审查工具 (Alibaba Open Code Review / OCR) 的多语言高确信度审查规则集。
规则设计遵循「高精确率优于召回率 (Precision over Recall)」原则，聚焦通用代码静态分析与对抗审查中高频且破坏力极大的确定性缺陷。

---

## 一、空指针与空引用安全 (Null / Nil Pointer Safety)

### 1. [RULE-NPE-GO-001] Go: 错误未校验即解引用指针
- **语言**: Go
- **严重等级**: HIGH
- **触发场景**: 函数返回 `(result, err)`，在未校验 `if err != nil` 的情况下直接访问 `result` 的成员或方法。
- **攻击与风险**: 当底层调用失败返回 `nil` 时，直接触发 `panic: runtime error: invalid memory address or nil pointer dereference`，造成服务进程崩溃。
- **修复示例**:
  ```go
  // 反例
  res, err := db.GetUser(id)
  return res.Name

  // 正例
  res, err := db.GetUser(id)
  if err != nil {
      return "", fmt.Errorf("get user %s failed: %w", id, err)
  }
  return res.Name, nil
  ```

### 2. [RULE-NPE-JAVA-001] Java: Optional / 集合检索直接链式调用
- **语言**: Java
- **严重等级**: HIGH
- **触发场景**: `map.get(...)`、`stream().filter().findFirst()` 或返回可能为 `null` 的方法后直接链式调用成员方法。
- **攻击与风险**: 抛出 `java.lang.NullPointerException`，阻断业务请求。
- **修复示例**:
  ```java
  // 反例
  String role = userMap.get(userId).getRole();

  // 正例
  User user = userMap.get(userId);
  if (user != null) {
      String role = user.getRole();
  }
  ```

### 3. [RULE-NPE-TS-001] TypeScript/JavaScript: 深层属性无保护访问
- **语言**: TypeScript / JavaScript
- **严重等级**: HIGH
- **触发场景**: 从 HTTP 请求体、外部 API 响应或可选配置项中解构或深层访问多层嵌套字段（如 `req.body.user.profile.name`）。
- **攻击与风险**: 运行时抛出 `TypeError: Cannot read properties of undefined (reading 'profile')`。
- **修复示例**:
  ```typescript
  // 反例
  const email = req.body.user.profile.email;

  // 正例
  const email = req.body?.user?.profile?.email;
  ```

### 4. [RULE-NPE-PY-001] Python: 正则匹配或字典查找直接解引用
- **语言**: Python
- **严重等级**: MEDIUM
- **触发场景**: `re.search(...).group()` 或 `dict.get(...).strip()` 在未判断非 None 时直接解引用。
- **修复示例**:
  ```python
  # 反例
  match = re.search(r"id=(\d+)", query).group(1)

  # 正例
  m = re.search(r"id=(\d+)", query)
  match = m.group(1) if m else None
  ```

---

## 二、并发与协程安全 (Concurrency & Thread Safety)

### 1. [RULE-CONC-GO-001] Go: 无生命周期管理的 Goroutine 泄漏
- **语言**: Go
- **严重等级**: HIGH
- **触发场景**: 使用 `go func()` 启动并发任务，但未关联 `context.Context`、未捕获 panic 或未加入 `sync.WaitGroup` 追踪。
- **攻击与风险**: 当父级操作超时或取消时，后台 Goroutine 持续驻留占用内存，引发连接泄漏或 Goroutine 膨胀。
- **修复示例**:
  ```go
  // 正例：显式监听 ctx.Done() 并由 WaitGroup 同步
  wg.Add(1)
  go func(ctx context.Context) {
      defer wg.Done()
      select {
      case <-ctx.Done():
          return
      case data := <-ch:
          process(data)
      }
  }(ctx)
  ```

### 2. [RULE-CONC-GO-002] Go: 并发读写原生 Map
- **语言**: Go
- **严重等级**: HIGH
- **触发场景**: 在多个 Goroutine 中读写未加锁的标准 `map[K]V`。
- **攻击与风险**: Go 运行时检测到并发 map 读写直接触发致命崩溃：`fatal error: concurrent map read and map write`，不可被 `recover` 捕获。
- **修复准则**: 改用 `sync.RWMutex` 保护，或使用 `sync.Map`。

### 3. [RULE-CONC-JAVA-001] Java: 共享非线程安全集合与工具
- **语言**: Java
- **严重等级**: HIGH
- **触发场景**: 在 Controller / Service 等单例 Bean 中将 `SimpleDateFormat`、`HashMap`、`ArrayList` 声明为成员变量并在多线程共享使用。
- **修复准则**: 使用 `ConcurrentHashMap`，时间格式化改用 Java 8+ 的不可变 `DateTimeFormatter`。

---

## 三、安全防护与代码注入 (Security Vulnerabilities)

### 1. [RULE-SEC-SQLI-001] SQL 语句拼接注入
- **语言**: 通用 (Java, Go, Python, Node.js)
- **严重等级**: CRITICAL
- **触发场景**: 使用字符串格式化（`fmt.Sprintf`、`f"SELECT..."`、`"SELECT... " + param`）拼接动态 SQL，未通过预编译参数绑定。
- **修复准则**: 一律强制使用参数化查询占位符 (`?` 或 `$1`)。

### 2. [RULE-SEC-XSS-001] 前端非受信 HTML 注入 (XSS)
- **语言**: TypeScript / JavaScript
- **严重等级**: HIGH
- **触发场景**: 在 React 中使用 `dangerouslySetInnerHTML`，或直接操作 `element.innerHTML = userInput`。
- **修复准则**: 优先采用文本绑定，若必须渲染富文本需经 DOMPurify 严格消毒。

### 3. [RULE-SEC-TRAV-001] 路径穿越与任意文件读写
- **语言**: 通用
- **严重等级**: HIGH
- **触发场景**: 将用户传入的文件名直接传入 `os.path.join` 或 `filepath.Join`，未进行基础目录边界校验。
- **修复准则**: 统一通过规范化路径校验 (`relative_to` 或 `strings.HasPrefix`) 确保位于受限目录树内。

---

## 四、资源管理与连接泄露 (Resource Management)

### 1. [RULE-RES-GO-001] Go: HTTP 响应体未关闭
- **语言**: Go
- **严重等级**: HIGH
- **触发场景**: 调用 `http.Get(...)` 或 `client.Do(...)` 后未执行 `defer resp.Body.Close()`。
- **修复准则**:
  ```go
  resp, err := client.Do(req)
  if err != nil {
      return err
  }
  defer resp.Body.Close()
  ```

### 2. [RULE-RES-PY-001] Python: 文件与连接未显式在上下文管理器中释放
- **语言**: Python
- **严重等级**: MEDIUM
- **触发场景**: 使用裸 `f = open(...)` 而未使用 `with open(...) as f:`。
- **修复准则**: 资源分配一律收敛于上下文管理器。

---

## 五、错误传播与鲁棒性 (Error Handling)

### 1. [RULE-ERR-SWALLOW-001] 空 Catch / 宽泛异常吞没
- **语言**: 通用
- **严重等级**: HIGH
- **触发场景**: `except Exception: pass`、`catch (Exception e) {}` 或 Go 中将关键返回值抛弃 `_ = file.Close()`。
- **修复准则**: 严禁静默忽略失败，至少记录日志或按契约向上传播结构化错误。
