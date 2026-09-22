#!/usr/bin/env python3
"""test-adversary CLI 执行器：用于代码与 Agent 资产的红队对抗审查、测试断言有效性审计、边界测试与代码审查。

遵循宪法 II：纯 Python 3 标准库实现，零外部依赖，跨平台 UTF-8/LF 确定性输出。
对齐阿里 open-code-review (OCR) 混合架构：确定性流水线 + agy 委派审查。

用法:
    python adversary_runner.py scan --dir <目标路径> [--mode code|agent|all] [--json] [--strict]
    python adversary_runner.py audit-test --dir <测试路径> [--json] [--strict]
    python adversary_runner.py run --dir <测试路径> [-v] [--json] [--strict]
    python adversary_runner.py review [--workspace|--staged|--from <base> --to <head>|--commit <hash>|--diff-file <path>]
                                      [--mode delegate|scan|native] [--preview] [--json] [--strict]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Optional

EXIT_OK = 0
EXIT_DEFECT = 1
EXIT_USAGE = 2

# 对抗风险模式（代码级与 Agent 资产级）
CODE_VULN_PATTERNS = [
    {
        "id": "ADV-CODE-001",
        "name": "Unsafe Deserialization / Exec",
        "severity": "HIGH",
        "pattern": re.compile(r"(?:pickle\.loads?|yaml\.load\([^)]*Loader\s*=\s*(?:yaml\.)?Loader|\beval\s*\(|\bexec\s*\()"),
        "message": "检测到不安全的反序列化或动态代码执行，极易导致代码执行漏洞",
        "fix": "避免 eval/exec，序列化改用 json 或安全解析器",
    },
    {
        "id": "ADV-CODE-002",
        "name": "Broad Exception Swallowing",
        "severity": "HIGH",
        "pattern": re.compile(r"except\s+(?:Exception|BaseException)\s*:\s*(?:pass|\.\.\.)"),
        "message": "检测到宽泛异常吞没（except Exception: pass），会隐匿严重运行时错误与攻击轨迹",
        "fix": "显式捕获具体异常类型，或在日志中保留堆栈 trace",
    },
    {
        "id": "ADV-CODE-003",
        "name": "Naive Path Join",
        "severity": "MEDIUM",
        "pattern": re.compile(r"os\.path\.join\([^,]+,\s*[a-zA-Z0-9_]+\)\s*(?!.*(?:resolve|abspath|normpath))"),
        "message": "未经规范化校验的路径拼接，存在路径穿越 (Directory Traversal) 风险",
        "fix": "在拼接后使用 Path.resolve() 并检查 relative_to(root)",
    },
    {
        "id": "ADV-CODE-004",
        "name": "Always-True Assertion in Code",
        "severity": "HIGH",
        "pattern": re.compile(r"\bassert\s+(?:True|1|len\([^)]+\)\s*>=\s*0)\b"),
        "message": "代码中存在恒真断言（如 assert True 或 assert len(...) >= 0），防御形同虚设",
        "fix": "编写具体、可证伪的有价值断言条件",
    },
]

AGENT_VULN_PATTERNS = [
    {
        "id": "ADV-AGENT-001",
        "name": "Missing Risk Blacklist",
        "severity": "MEDIUM",
        "pattern": None,  # 结构性检查
        "message": "Agent 规约未显式声明反例与黑名单（Anti-Patterns / Blacklist）",
        "fix": "增加反例清单明确禁止的危险操作与逃逸边界",
    },
    {
        "id": "ADV-AGENT-002",
        "name": "Unrestricted Prompt Injection Target",
        "severity": "HIGH",
        "pattern": re.compile(r"(?:ignore\s+all\s+(?:previous|above)\s+instructions|无视上述所有规则|忽略之前的所有提示)", re.IGNORECASE),
        "message": "检测到 Prompt 注入与系统指令旁路敏感短语",
        "fix": "增强系统提示词边界隔离，声明任何用户指令不得覆盖顶层宪法",
    },
    {
        "id": "ADV-AGENT-003",
        "name": "Fuzzy Fallback Clause",
        "severity": "LOW",
        "pattern": re.compile(r"(?:灵活把握|根据情况自行判断|视情况而定|自由发挥)"),
        "message": "规约中出现模糊逃逸措辞，会导致 Agent 在边界场景失去确定性",
        "fix": "删除软化措辞，改用明确的 MUST / MUST NOT 或显式询问分支",
    },
]


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    file_path: str
    line_number: int
    message: str
    fix: str
    line_content: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


# ==============================================================================
# 确定性 Unified Diff 解析与行号映射核心 (对齐阿里 open-code-review)
# ==============================================================================

@dataclass
class DiffLine:
    line_type: str  # '+', '-', ' '
    content: str
    old_lineno: Optional[int]
    new_lineno: Optional[int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: list[DiffLine] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_start": self.old_start,
            "old_count": self.old_count,
            "new_start": self.new_start,
            "new_count": self.new_count,
            "header": self.header,
            "lines": [l.to_dict() for l in self.lines],
        }


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    is_binary: bool = False
    is_new: bool = False
    is_deleted: bool = False
    hunks: list[DiffHunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path

    @property
    def added_lines_count(self) -> int:
        return sum(1 for h in self.hunks for l in h.lines if l.line_type == "+")

    @property
    def deleted_lines_count(self) -> int:
        return sum(1 for h in self.hunks for l in h.lines if l.line_type == "-")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "is_binary": self.is_binary,
            "is_new": self.is_new,
            "is_deleted": self.is_deleted,
            "added_lines": self.added_lines_count,
            "deleted_lines": self.deleted_lines_count,
            "hunks": [h.to_dict() for h in self.hunks],
        }


class FileNoiseFilter:
    """过滤无代码审查价值的噪点文件（依赖锁文件、二进制、打包编译产物等）。"""

    NOISE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".tgz", ".7z",
        ".exe", ".dll", ".so", ".dylib", ".bin",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pyc", ".pyo", ".class", ".o", ".obj",
        ".min.js", ".min.css", ".map",
    }

    NOISE_FILENAMES = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.lock",
        "poetry.lock",
        "go.sum",
        "composer.lock",
        "pipfile.lock",
        "gemfile.lock",
        "flake.lock",
    }

    NOISE_DIRS = {
        "node_modules",
        "dist",
        "build",
        "vendor",
        "target",
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".venv",
        "venv",
        ".next",
        ".nuxt",
        "coverage",
    }

    @classmethod
    def is_noise(cls, file_path: str) -> bool:
        normalized = file_path.replace("\\", "/").strip()
        parts = normalized.split("/")
        for part in parts[:-1]:
            if part in cls.NOISE_DIRS:
                return True
        filename = parts[-1].lower()
        if filename in cls.NOISE_FILENAMES:
            return True
        for ext in cls.NOISE_EXTENSIONS:
            if filename.endswith(ext):
                return True
        if filename.endswith(("_pb2.py", "_pb2_grpc.py", ".pb.go", ".generated.ts", ".generated.go")):
            return True
        return False


class DiffParser:
    """解析 Unified Diff 文本并计算确切的新旧行号映射。"""

    HUNK_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$")

    @classmethod
    def parse(cls, diff_text: str) -> list[FileDiff]:
        files: list[FileDiff] = []
        current_file: Optional[FileDiff] = None
        current_hunk: Optional[DiffHunk] = None
        cur_old = 0
        cur_new = 0

        lines = normalize_newlines(diff_text).split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith("diff --git "):
                parts = line.split(" ")
                old_p = parts[2][2:] if parts[2].startswith("a/") else parts[2]
                new_p = parts[3][2:] if parts[3].startswith("b/") else parts[3]
                current_file = FileDiff(old_path=old_p, new_path=new_p)
                files.append(current_file)
                current_hunk = None
                i += 1
                continue

            if line.startswith("Binary files ") and "differ" in line:
                if current_file:
                    current_file.is_binary = True
                i += 1
                continue

            if line.startswith("--- "):
                path_part = line[4:].strip()
                if path_part.startswith("a/"):
                    path_part = path_part[2:]
                if current_file is None:
                    current_file = FileDiff(old_path=path_part, new_path=path_part)
                    files.append(current_file)
                else:
                    current_file.old_path = path_part
                if path_part == "/dev/null":
                    current_file.is_new = True
                i += 1
                continue

            if line.startswith("+++ "):
                path_part = line[4:].strip()
                if path_part.startswith("b/"):
                    path_part = path_part[2:]
                if current_file is None:
                    current_file = FileDiff(old_path=path_part, new_path=path_part)
                    files.append(current_file)
                else:
                    current_file.new_path = path_part
                if path_part == "/dev/null":
                    current_file.is_deleted = True
                i += 1
                continue

            hunk_match = cls.HUNK_RE.match(line)
            if hunk_match:
                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4)) if hunk_match.group(4) is not None else 1

                current_hunk = DiffHunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    header=line,
                )
                if current_file is None:
                    current_file = FileDiff(old_path="unknown", new_path="unknown")
                    files.append(current_file)
                current_file.hunks.append(current_hunk)
                cur_old = old_start
                cur_new = new_start
                i += 1
                continue

            if current_hunk is not None:
                if line.startswith("+"):
                    diff_line = DiffLine(
                        line_type="+",
                        content=line[1:],
                        old_lineno=None,
                        new_lineno=cur_new,
                    )
                    current_hunk.lines.append(diff_line)
                    cur_new += 1
                elif line.startswith("-"):
                    diff_line = DiffLine(
                        line_type="-",
                        content=line[1:],
                        old_lineno=cur_old,
                        new_lineno=None,
                    )
                    current_hunk.lines.append(diff_line)
                    cur_old += 1
                elif line.startswith(" "):
                    diff_line = DiffLine(
                        line_type=" ",
                        content=line[1:],
                        old_lineno=cur_old,
                        new_lineno=cur_new,
                    )
                    current_hunk.lines.append(diff_line)
                    cur_old += 1
                    cur_new += 1
                elif line.startswith("\\"):
                    pass
                elif not line.strip() and i == len(lines) - 1:
                    pass

            i += 1

        return files


class GitDiffExtractor:
    """从 Git 或 diff 文件中提取变更 Unified Diff。"""

    @classmethod
    def get_diff(
        cls,
        repo_dir: Path,
        workspace: bool = False,
        staged: bool = False,
        from_ref: Optional[str] = None,
        to_ref: Optional[str] = None,
        commit: Optional[str] = None,
        diff_file: Optional[str] = None,
    ) -> str:
        if diff_file:
            p = Path(diff_file)
            if not p.is_absolute():
                p = repo_dir / p
            if not p.exists():
                raise FileNotFoundError(f"Diff 文件未找到: {p}")
            return p.read_text(encoding="utf-8", errors="replace")

        if not shutil.which("git"):
            raise RuntimeError("系统 PATH 中未找到 git 命令，且未提供 --diff-file。")

        check_repo = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
        )
        if check_repo.returncode != 0:
            raise RuntimeError(
                f"目标目录不是有效的 Git 仓库: {repo_dir}。\n"
                f"提示: 请在 Git 仓库中执行代码审查，或通过 --diff-file <path> 指定 Unified Diff 文件。"
            )

        cmd = ["git"]
        if commit:
            cmd.extend(["diff", f"{commit}~1", commit, "--"])
        elif from_ref and to_ref:
            cmd.extend(["diff", f"{from_ref}..{to_ref}", "--"])
        elif from_ref:
            cmd.extend(["diff", from_ref, "--"])
        elif staged:
            cmd.extend(["diff", "--cached", "--"])
        else:
            check_head = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD"],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
            )
            if check_head.returncode == 0:
                cmd.extend(["diff", "HEAD", "--"])
            else:
                cmd.extend(["diff", "--"])

        res = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode != 0:
            raise RuntimeError(f"Git 命令执行失败 ({' '.join(cmd)}): {res.stderr.strip()}")
        return res.stdout


# ==============================================================================
# 多语言工业级确定性规则引擎 (Industrial Ruleset)
# ==============================================================================

class IndustrialRuleset:
    """对齐阿里开源 OCR 的多语言高确信度确定性规则库。"""

    @classmethod
    def check_file_diff(cls, file_diff: FileDiff) -> list[Finding]:
        findings: list[Finding] = []
        if file_diff.is_binary or file_diff.is_deleted:
            return findings

        path_str = file_diff.path
        ext = Path(path_str).suffix.lower()

        for hunk in file_diff.hunks:
            hunk_added_lines = [l for l in hunk.lines if l.line_type == "+"]
            hunk_full_text = "\n".join(l.content for l in hunk.lines)

            # --- 1. Go NPE & 资源泄露 & 协程安全 ---
            if ext == ".go":
                # RULE-NPE-GO-001: 返回错误未校验即直接解引用结果指针
                err_assign_match = re.search(r"\b([a-zA-Z0-9_]+),\s*err\s*:=", hunk_full_text)
                if err_assign_match and "err != nil" not in hunk_full_text:
                    ret_var = err_assign_match.group(1)
                    for line in hunk_added_lines:
                        if re.search(rf"\b{re.escape(ret_var)}\.[A-Z]", line.content):
                            findings.append(
                                Finding(
                                    rule_id="RULE-NPE-GO-001",
                                    name="Go Unchecked Error Dereference",
                                    severity="HIGH",
                                    file_path=path_str,
                                    line_number=line.new_lineno or hunk.new_start,
                                    line_content=line.content.strip(),
                                    message="函数返回错误未校验即直接解引用结果指针，极易触发 nil pointer 崩溃",
                                    fix="在解引用前补充 `if err != nil { return ..., err }`",
                                )
                            )
                            break

                # RULE-CONC-GO-001: 无生命周期管理的 Goroutine 泄漏
                for line in hunk_added_lines:
                    if re.search(r"\bgo\s+func\s*\(", line.content):
                        if "ctx" not in hunk_full_text and "Done()" not in hunk_full_text and "WaitGroup" not in hunk_full_text:
                            findings.append(
                                Finding(
                                    rule_id="RULE-CONC-GO-001",
                                    name="Go Unmanaged Goroutine Leak",
                                    severity="HIGH",
                                    file_path=path_str,
                                    line_number=line.new_lineno or hunk.new_start,
                                    line_content=line.content.strip(),
                                    message="启动后台 Goroutine 未关联 Context 生命周期或 sync.WaitGroup，存在协程泄漏隐患",
                                    fix="传入 ctx 监听 ctx.Done()，或使用 sync.WaitGroup 保证退出协同",
                                )
                            )

                # RULE-RES-GO-001: HTTP 响应体未关闭
                if re.search(r"\bhttp\.(?:Get|Post|Do)\s*\(", hunk_full_text):
                    if not re.search(r"\bdefer\s+[a-zA-Z0-9_]+\.Body\.Close\(\)", hunk_full_text):
                        findings.append(
                            Finding(
                                rule_id="RULE-RES-GO-001",
                                name="Go HTTP Response Body Not Closed",
                                severity="HIGH",
                                file_path=path_str,
                                line_number=hunk.new_start,
                                line_content="http.Get/Post/Do",
                                message="发起 HTTP 请求后未执行 defer resp.Body.Close()，会导致连接与句柄泄漏",
                                fix="在检查 err == nil 后增加 `defer resp.Body.Close()`",
                            )
                        )

            # --- 2. Java NPE & 并发集合安全 ---
            if ext == ".java":
                for line in hunk_added_lines:
                    text = line.content
                    # RULE-NPE-JAVA-001: 链式调用
                    if re.search(r"(?:Map|Cache)\.get\([^)]+\)\.[a-zA-Z0-9_]+", text) or re.search(r"\.findFirst\(\)\.get\(", text):
                        findings.append(
                            Finding(
                                rule_id="RULE-NPE-JAVA-001",
                                name="Java Chained Call on Potentially Null Object",
                                severity="HIGH",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="对 Map.get() 或 findFirst().get() 进行无保护链式调用，存在 NullPointerException 风险",
                                fix="先进行 null 判断，或使用 Optional.orElseThrow / orElse",
                            )
                        )

                    # RULE-CONC-JAVA-001: 共享非线程安全成员
                    if re.search(r"(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?(?:SimpleDateFormat|HashMap|ArrayList)\b", text):
                        findings.append(
                            Finding(
                                rule_id="RULE-CONC-JAVA-001",
                                name="Java Shared Non-Threadsafe Collection in Class Field",
                                severity="HIGH",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="在类成员中声明非线程安全集合或 SimpleDateFormat，多线程环境下存在并发竞争",
                                fix="改用 ConcurrentHashMap，时间格式化改用不可变 DateTimeFormatter",
                            )
                        )

            # --- 3. TypeScript / JavaScript 深层属性访问与 XSS ---
            if ext in (".ts", ".tsx", ".js", ".jsx"):
                for line in hunk_added_lines:
                    text = line.content
                    # RULE-NPE-TS-001: 深层嵌套属性无可选链
                    if re.search(r"(?:req\.body|response\.data|ctx\.request)\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+", text):
                        if "?." not in text:
                            findings.append(
                                Finding(
                                    rule_id="RULE-NPE-TS-001",
                                    name="TypeScript Deep Nested Property Access",
                                    severity="HIGH",
                                    file_path=path_str,
                                    line_number=line.new_lineno or hunk.new_start,
                                    line_content=text.strip(),
                                    message="外部响应或请求体多层深层解引用未采用可选链保护（?.），缺失属性将抛出 TypeError",
                                    fix="使用可选链操作符 `?.` 进行防御性访问",
                                )
                            )

                    # RULE-SEC-XSS-001: 前端非受信 HTML 注入
                    if re.search(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", text) or re.search(r"\.innerHTML\s*=\s*", text):
                        findings.append(
                            Finding(
                                rule_id="RULE-SEC-XSS-001",
                                name="XSS Unsafe HTML Injection",
                                severity="HIGH",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="使用 dangerouslySetInnerHTML 或 innerHTML 直接注入内容，存在 XSS 攻击风险",
                                fix="改用纯文本渲染，或使用 DOMPurify 进行严格净化",
                            )
                        )

            # --- 4. Python NPE & 资源安全 ---
            if ext == ".py":
                for line in hunk_added_lines:
                    text = line.content
                    # RULE-NPE-PY-001: 正则或字典未判空直接解引用
                    if re.search(r"re\.(?:search|match)\([^)]+\)\.group\(", text) or re.search(r"\.get\([^)]+\)\.(?:strip|lower|upper|split)\(", text):
                        findings.append(
                            Finding(
                                rule_id="RULE-NPE-PY-001",
                                name="Python Unchecked Method Call on Optional Result",
                                severity="MEDIUM",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="对 re.search 或 dict.get 返回值未判断 None 即直接解引用调用方法",
                                fix="显式判断返回值非 None 或提供安全默认值",
                            )
                        )

                    # RULE-RES-PY-001: 裸 open 未在 with 中使用
                    if re.search(r"^[ \t]*(?:f|fp|file)\s*=\s*open\([^)]+\)", text):
                        findings.append(
                            Finding(
                                rule_id="RULE-RES-PY-001",
                                name="Python Bare File Open Without Context Manager",
                                severity="MEDIUM",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="使用裸 open(...) 分配文件句柄，未通过 with 上下文管理器管理可能导致句柄泄漏",
                                fix="改用 `with open(...) as f:` 确保文件句柄确定性关闭",
                            )
                        )

            # --- 5. 通用规则：SQL 注入、路径穿越、异常吞没 ---
            for line in hunk_added_lines:
                text = line.content

                # RULE-SEC-SQLI-001: 动态字符串拼接 SQL
                if re.search(r"(?:execute|cursor\.execute|db\.Query|db\.Exec|executeQuery)\s*\(\s*f[\"'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b", text, re.IGNORECASE) or \
                   re.search(r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*[\"']\s*\+\s*[a-zA-Z0-9_]+", text, re.IGNORECASE) or \
                   re.search(r"fmt\.Sprintf\s*\(\s*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE)\b", text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id="RULE-SEC-SQLI-001",
                            name="SQL String Formatting Injection",
                            severity="CRITICAL",
                            file_path=path_str,
                            line_number=line.new_lineno or hunk.new_start,
                            line_content=text.strip(),
                            message="使用动态字符串拼接构建 SQL 查询，存在高危 SQL 注入漏洞",
                            fix="强制使用参数化预编译占位符传递参数",
                        )
                    )

                # RULE-SEC-TRAV-001: 路径拼接缺少规范化边界校验
                if re.search(r"(?:os\.path\.join|filepath\.Join)\([^)]*(?:user_input|request\.|req\.|param|filename)", text):
                    if "resolve" not in hunk_full_text and "abspath" not in hunk_full_text and "Clean" not in hunk_full_text:
                        findings.append(
                            Finding(
                                rule_id="RULE-SEC-TRAV-001",
                                name="Unsanitized Path Traversal",
                                severity="HIGH",
                                file_path=path_str,
                                line_number=line.new_lineno or hunk.new_start,
                                line_content=text.strip(),
                                message="外部输入直接拼接至路径且未校验基础路径边界，存在目录穿越与任意文件读写风险",
                                fix="进行规范化解析并确保路径位于根目录下（如 resolve + relative_to）",
                            )
                        )

                # RULE-ERR-SWALLOW-001: 异常吞没或忽略关键错误
                if re.search(r"except\s+(?:Exception|BaseException)\s*:\s*(?:pass|\.\.\.)", text) or \
                   re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", text) or \
                   re.search(r"_\s*=\s*(?:[a-zA-Z0-9_]+\.)?(?:Close|Remove|Write|Flush)\(", text):
                    findings.append(
                        Finding(
                            rule_id="RULE-ERR-SWALLOW-001",
                            name="Broad Exception or Critical Error Swallowed",
                            severity="HIGH",
                            file_path=path_str,
                            line_number=line.new_lineno or hunk.new_start,
                            line_content=text.strip(),
                            message="捕获异常后静默吞没，或显式丢弃关键 I/O 操作返回的错误，隐匿系统故障",
                            fix="记录错误日志或按契约向上传播结构化错误",
                        )
                    )

        return findings


# ==============================================================================
# agy 委派模式组包器 (Delegation Packager)
# ==============================================================================

class DelegationPackager:
    """组装针对 agy CLI / Antigravity Agent 的审查上下文与委派提示词。"""

    @classmethod
    def build_package(
        cls,
        target_desc: str,
        reviewable_files: list[FileDiff],
        noise_files: list[FileDiff],
        findings: list[Finding],
    ) -> dict[str, Any]:
        total_hunks = sum(len(f.hunks) for f in reviewable_files)
        total_added = sum(f.added_lines_count for f in reviewable_files)
        total_deleted = sum(f.deleted_lines_count for f in reviewable_files)

        prompt_lines = [
            "# Antigravity / agy 代码审查委派指令 (Code Review Delegation)",
            "",
            "## 1. 变更概览",
            f"- 目标: {target_desc}",
            f"- 待审查文件数: {len(reviewable_files)} 个 | 过滤噪点文件: {len(noise_files)} 个",
            f"- 代码行变动: +{total_added} / -{total_deleted} (共 {total_hunks} 个 Hunk)",
            f"- 确定性规则初筛命中: {len(findings)} 处",
            "",
            "## 2. 审查任务要求",
            "你正在以「测试与对抗审查红队工程师」身份对本次变更进行深度审查：",
            "1. **核实确定性规则候选**：对流水线初筛命中的规则候选逐一核实。若确认违规，保留并给出针对性修复；若代码已有上游防御证明安全，说明排除原因。",
            "2. **深度语义与对抗审查**：检查业务逻辑完备性、边界条件、并发竞争、异常传播与单测覆盖缺失。",
            "3. **行级精确定位**：批注必须且只能绑定在 Diff 实际给出的行号 (line_number) 上，严禁出现不存在的行号。",
            "4. **严格零 Emoji**：所有审查反馈严禁使用 Emoji 图标，保持专业技术报告风格。",
            "",
            "## 3. 审查产出标准 Markdown 表格",
            "| 文件路径 | 行号 | 严重级别 | 审查维度 / 规则 ID | 缺陷分析与修复建议 |",
            "|---|---|---|---|---|",
            "",
            "## 4. 待审查 Diff Hunks 详情",
        ]

        for f in reviewable_files:
            prompt_lines.append(f"### 文件: `{f.path}` (+{f.added_lines_count}, -{f.deleted_lines_count})")
            file_findings = [x for x in findings if x.file_path == f.path]
            if file_findings:
                prompt_lines.append(f"**流水线命中候选 ({len(file_findings)} 处)**:")
                for ff in file_findings:
                    prompt_lines.append(f"- [行 {ff.line_number}] [{ff.severity}] {ff.rule_id}: {ff.message}")
            prompt_lines.append("```diff")
            for h in f.hunks:
                prompt_lines.append(h.header)
                for l in h.lines:
                    line_no = f" [L{l.new_lineno}]" if l.new_lineno else ""
                    prompt_lines.append(f"{l.line_type}{l.content}{line_no}")
            prompt_lines.append("```\n")

        delegation_prompt = "\n".join(prompt_lines)

        return {
            "summary": {
                "target": target_desc,
                "files_scanned": len(reviewable_files),
                "files_filtered": len(noise_files),
                "filtered_files": [f.path for f in noise_files],
                "hunks_count": total_hunks,
                "lines_added": total_added,
                "lines_deleted": total_deleted,
                "candidate_rule_hits": len(findings),
            },
            "candidate_findings": [f.to_dict() for f in findings],
            "review_units": [
                {
                    "path": f.path,
                    "is_new": f.is_new,
                    "is_deleted": f.is_deleted,
                    "added_lines": f.added_lines_count,
                    "deleted_lines": f.deleted_lines_count,
                    "findings": [x.to_dict() for x in findings if x.file_path == f.path],
                    "hunks": [h.to_dict() for h in f.hunks],
                }
                for f in reviewable_files
            ],
            "delegation_prompt": delegation_prompt,
        }


# ==============================================================================
# 代码扫描与单测审计实现
# ==============================================================================

def scan_code_file(path: Path, findings: list[Finding]) -> None:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    try:
        tree = ast.parse(content, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                is_broad = False
                if node.type is None:
                    is_broad = True
                elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
                    is_broad = True

                if is_broad:
                    is_swallowed = False
                    if len(node.body) == 1:
                        stmt = node.body[0]
                        if isinstance(stmt, ast.Pass):
                            is_swallowed = True
                        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                            is_swallowed = True
                    if is_swallowed:
                        findings.append(
                            Finding(
                                rule_id="ADV-CODE-002",
                                name="Broad Exception Swallowing",
                                severity="HIGH",
                                file_path=str(path),
                                line_number=node.lineno,
                                message="检测到宽泛异常吞没（except Exception: pass），会隐匿严重运行时错误与攻击轨迹",
                                fix="显式捕获具体异常类型，或在日志中保留堆栈 trace",
                            )
                        )
            elif isinstance(node, ast.Assert):
                if isinstance(node.test, ast.Constant) and bool(node.test.value) is True:
                    findings.append(
                        Finding(
                            rule_id="ADV-CODE-004",
                            name="Always-True Assertion in Code",
                            severity="HIGH",
                            file_path=str(path),
                            line_number=node.lineno,
                            message="代码中存在恒真断言（如 assert True 或 assert 1），防御形同虚设",
                            fix="编写具体、可证伪的有价值断言条件",
                        )
                    )
    except (SyntaxError, ValueError):
        return

    lines = normalize_newlines(content).split("\n")
    for i, line in enumerate(lines, 1):
        for pattern_info in CODE_VULN_PATTERNS:
            if pattern_info["id"] in ("ADV-CODE-002", "ADV-CODE-004"):
                continue
            regex = pattern_info["pattern"]
            if regex and regex.search(line):
                findings.append(
                    Finding(
                        rule_id=pattern_info["id"],
                        name=pattern_info["name"],
                        severity=pattern_info["severity"],
                        file_path=str(path),
                        line_number=i,
                        message=pattern_info["message"],
                        fix=pattern_info["fix"],
                    )
                )


def scan_agent_file(path: Path, findings: list[Finding]) -> None:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = normalize_newlines(content).split("\n")
    has_blacklist = False
    for i, line in enumerate(lines, 1):
        if re.search(r"(?:反例|黑名单|blacklist|anti-patterns|禁止行为)", line, re.IGNORECASE):
            has_blacklist = True

        for pattern_info in AGENT_VULN_PATTERNS:
            regex = pattern_info["pattern"]
            if line.strip().startswith(("- **脆弱模式**:", "- **漏洞模式**:", ">", "*")):
                continue
            if regex and regex.search(line):
                findings.append(
                    Finding(
                        rule_id=pattern_info["id"],
                        name=pattern_info["name"],
                        severity=pattern_info["severity"],
                        file_path=str(path),
                        line_number=i,
                        message=pattern_info["message"],
                        fix=pattern_info["fix"],
                    )
                )

    if not has_blacklist and path.name.lower() in ("skill.md", "prompt.md"):
        findings.append(
            Finding(
                rule_id="ADV-AGENT-001",
                name="Missing Risk Blacklist",
                severity="MEDIUM",
                file_path=str(path),
                line_number=1,
                message="Skill 契约中未包含反例或黑名单章节",
                fix="在文档中增加 ## 反例与黑名单 章节以规范负向边界",
            )
        )


def audit_test_file(path: Path, findings: list[Finding]) -> None:
    """使用 AST 深度审计 Python 单元测试的断言有效性与假阳性。"""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(path))
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="ADV-TEST-PARSE",
                name="Test File Parse Error",
                severity="HIGH",
                file_path=str(path),
                line_number=1,
                message=f"测试文件 AST 解析失败: {exc}",
                fix="修复 Python 语法错误",
            )
        )
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            assertions = []
            for child in ast.walk(node):
                if isinstance(child, ast.Assert):
                    assertions.append(child)
                    if isinstance(child.test, ast.Constant) and bool(child.test.value) is True:
                        findings.append(
                            Finding(
                                rule_id="ADV-TEST-001",
                                name="Constant True Assertion",
                                severity="HIGH",
                                file_path=str(path),
                                line_number=child.lineno,
                                message=f"测试用例 {node.name} 中存在恒真断言 (assert True)，无法起到验证效果",
                                fix="断言真实返回值或状态",
                            )
                        )
                elif isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute) and child.func.attr.startswith("assert"):
                        assertions.append(child)
                        if child.func.attr == "assertTrue":
                            if child.args and isinstance(child.args[0], ast.Constant) and bool(child.args[0].value) is True:
                                findings.append(
                                    Finding(
                                        rule_id="ADV-TEST-002",
                                        name="Constant assertTrue(True)",
                                        severity="HIGH",
                                        file_path=str(path),
                                        line_number=child.lineno,
                                        message=f"测试用例 {node.name} 中存在 self.assertTrue(True) 假阳性测试",
                                        fix="断言真实测试结果",
                                    )
                                )

            if not assertions:
                findings.append(
                    Finding(
                        rule_id="ADV-TEST-003",
                        name="Assertion-Free Test (Ghost Test)",
                        severity="HIGH",
                        file_path=str(path),
                        line_number=node.lineno,
                        message=f"测试方法 {node.name} 中无任何断言语句，为无效的空运行测试（假绿灯）",
                        fix="补充显式 assert 或 self.assertEqual 等校验",
                    )
                )


# ==============================================================================
# CLI 命令实现
# ==============================================================================

def cmd_scan(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(f"[ERROR] 目标路径不存在: {target_dir}", file=sys.stderr)
        return EXIT_USAGE

    findings: list[Finding] = []
    mode = args.mode

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            d for d in dirs
            if d not in (".git", "__pycache__", ".pytest_cache", "target", "node_modules", "vendor", "dist", "build")
        ]
        for fname in files:
            p = Path(root) / fname
            is_test_file = "tests" in p.parts or fname.startswith("test_")
            if p.suffix == ".py" and mode in ("code", "all") and not is_test_file:
                scan_code_file(p, findings)
            if p.suffix in (".md", ".txt", ".json") and mode in ("agent", "all"):
                scan_agent_file(p, findings)

    return _render_findings(findings, args.json, args.strict)


def cmd_audit_test(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(f"[ERROR] 测试目录不存在: {target_dir}", file=sys.stderr)
        return EXIT_USAGE

    findings: list[Finding] = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            p = Path(root) / fname
            if p.suffix == ".py" and ("test" in p.name.lower()):
                audit_test_file(p, findings)

    return _render_findings(findings, args.json, args.strict)


def cmd_run(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(f"[ERROR] 测试目录不存在: {target_dir}", file=sys.stderr)
        return EXIT_USAGE

    print(f"=== 运行测试套件与对抗分析: {target_dir} ===")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(target_dir), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)

    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success = result.wasSuccessful()

    summary = {
        "testsRun": total,
        "failures": failures,
        "errors": errors,
        "success": success,
    }

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(f"\n[SUMMARY] 运行测试: {total} | 失败: {failures} | 错误: {errors}")
        if success:
            print("[PASS] 测试套件全部通过！")
        else:
            print("[FAIL] 测试套件存在未通过用例！", file=sys.stderr)

    return EXIT_OK if success else EXIT_DEFECT


def cmd_review(args: argparse.Namespace) -> int:
    repo_dir = Path(args.dir).resolve()
    if not repo_dir.exists():
        print(f"[ERROR] 目标目录不存在: {repo_dir}", file=sys.stderr)
        return EXIT_USAGE

    target_desc = "workspace"
    if args.commit:
        target_desc = f"commit {args.commit}"
    elif args.from_ref and args.to_ref:
        target_desc = f"branch diff {args.from_ref}..{args.to_ref}"
    elif args.from_ref:
        target_desc = f"diff vs {args.from_ref}"
    elif args.staged:
        target_desc = "staged changes"
    elif args.diff_file:
        target_desc = f"diff file: {args.diff_file}"

    # 1. 提取 Unified Diff
    try:
        diff_text = GitDiffExtractor.get_diff(
            repo_dir=repo_dir,
            workspace=args.workspace,
            staged=args.staged,
            from_ref=args.from_ref,
            to_ref=args.to_ref,
            commit=args.commit,
            diff_file=args.diff_file,
        )
    except Exception as exc:
        print(f"[ERROR] 无法提取 Diff: {exc}", file=sys.stderr)
        return EXIT_DEFECT

    # 2. 解析 Diff 结构
    all_files = DiffParser.parse(diff_text)
    reviewable_files = [f for f in all_files if not FileNoiseFilter.is_noise(f.path) and not f.is_binary]
    noise_files = [f for f in all_files if FileNoiseFilter.is_noise(f.path) or f.is_binary]

    total_hunks = sum(len(f.hunks) for f in reviewable_files)
    total_added = sum(f.added_lines_count for f in reviewable_files)
    total_deleted = sum(f.deleted_lines_count for f in reviewable_files)

    # 3. 预检模式处理
    if args.preview:
        if args.json:
            preview_data = {
                "target": target_desc,
                "reviewable_files_count": len(reviewable_files),
                "noise_files_count": len(noise_files),
                "lines_added": total_added,
                "lines_deleted": total_deleted,
                "hunks_count": total_hunks,
                "reviewable_files": [f.path for f in reviewable_files],
                "noise_files": [f.path for f in noise_files],
            }
            print(json.dumps(preview_data, indent=2, ensure_ascii=False))
        else:
            print("=== 代码审查预检评估 (Review Preview) ===")
            print(f"目标: {target_desc}")
            print(f"待审查文件数: {len(reviewable_files)} 个")
            print(f"已过滤噪点数: {len(noise_files)} 个")
            print(f"代码增删量: +{total_added} / -{total_deleted} (共 {total_hunks} 个 Hunk)\n")
            if reviewable_files:
                print("待审查文件列表:")
                for rf in reviewable_files:
                    print(f"  - {rf.path} (+{rf.added_lines_count}, -{rf.deleted_lines_count}) [{len(rf.hunks)} hunks]")
            if noise_files:
                print("\n已过滤噪点文件:")
                for nf in noise_files:
                    print(f"  - {nf.path} (噪点过滤)")
        return EXIT_OK

    # 4. 原生 OCR 桥接检测
    if args.mode == "native":
        ocr_path = shutil.which("ocr")
        if ocr_path:
            print(f"[INFO] 检测到原生 ocr 命令 ({ocr_path})，桥接调用原生引擎...")
            ocr_cmd = ["ocr", "review"]
            if args.staged:
                ocr_cmd.append("--staged")
            res = subprocess.run(ocr_cmd, cwd=str(repo_dir))
            return res.returncode
        else:
            print("[NOTICE] 未检测到原生 ocr 命令，自动使用内置确定性流水线 + agy 委派模式执行。", file=sys.stderr)

    # 5. 确定性规则库扫描
    findings: list[Finding] = []
    for f in reviewable_files:
        f_findings = IndustrialRuleset.check_file_diff(f)
        findings.extend(f_findings)

    # 6. 模式分流：scan 纯扫描 或 delegate 委派模式
    if args.mode == "scan":
        return _render_findings(findings, args.json, args.strict)

    # 委派模式 (delegate)
    package = DelegationPackager.build_package(
        target_desc=target_desc,
        reviewable_files=reviewable_files,
        noise_files=noise_files,
        findings=findings,
    )

    if args.json:
        print(json.dumps(package, indent=2, ensure_ascii=False))
    else:
        print(package["delegation_prompt"])

    if findings and args.strict:
        return EXIT_DEFECT
    return EXIT_OK


def _render_findings(findings: list[Finding], as_json: bool, strict: bool) -> int:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("[PASS] 对抗审查完成，未发现违规或脆弱点。")
        else:
            print(f"[ALERT] 发现 {len(findings)} 处潜在对抗弱点或断言隐患:\n")
            for f in findings:
                print(f"[{f.severity}] {f.rule_id}: {f.name}")
                print(f"  文件: {f.file_path}:{f.line_number}")
                if f.line_content:
                    print(f"  代码: {f.line_content}")
                print(f"  问题: {f.message}")
                print(f"  修复: {f.fix}\n")

    has_high = any(f.severity in ("HIGH", "CRITICAL") for f in findings)
    if findings and strict:
        return EXIT_DEFECT
    if has_high:
        return EXIT_DEFECT
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversary_runner.py",
        description="test-adversary CLI: 代码与 Agent 资产对抗审查、单测假阳性审计与自动化测试。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan 子命令
    p_scan = subparsers.add_parser("scan", help="静态扫描代码与 Agent 资产的对抗脆弱点")
    p_scan.add_argument("--dir", default=".", help="待扫描的目录路径（默认: 当前目录）")
    p_scan.add_argument("--mode", choices=["code", "agent", "all"], default="all", help="审查模式 (code/agent/all)")
    p_scan.add_argument("--json", action="store_true", help="输出 JSON 格式")
    p_scan.add_argument("--strict", action="store_true", help="严格模式（命中任何级别告警均以退出码 1 退出）")

    # audit-test 子命令
    p_audit = subparsers.add_parser("audit-test", help="审计单元测试断言有效性与假阳性（假绿灯）")
    p_audit.add_argument("--dir", default=".", help="测试用例目录路径")
    p_audit.add_argument("--json", action="store_true", help="输出 JSON 格式")
    p_audit.add_argument("--strict", action="store_true", help="严格模式")

    # run 子命令
    p_run = subparsers.add_parser("run", help="运行自动化测试并报告脆弱点")
    p_run.add_argument("--dir", default=".", help="测试用例目录路径")
    p_run.add_argument("-v", "--verbose", action="store_true", help="显示详细测试轨迹")
    p_run.add_argument("--json", action="store_true", help="输出 JSON 摘要")
    p_run.add_argument("--strict", action="store_true", help="严格模式")

    # review 子命令 (对齐阿里 open-code-review)
    p_review = subparsers.add_parser("review", help="对齐阿里 OCR 混合架构：确定性流水线 + agy 委派代码审查")
    p_review.add_argument("--dir", default=".", help="工作区根目录路径（默认: 当前目录）")
    p_review.add_argument("--workspace", action="store_true", help="审查工作区修改（默认）")
    p_review.add_argument("--staged", action="store_true", help="审查暂存区 (git diff --cached)")
    p_review.add_argument("--from", dest="from_ref", help="基准 commit 或分支 (git diff <from>..<to>)")
    p_review.add_argument("--to", dest="to_ref", help="目标 commit 或分支")
    p_review.add_argument("--commit", help="审查指定 commit")
    p_review.add_argument("--diff-file", help="从指定的 unified diff 文件中读取")
    p_review.add_argument("--mode", choices=["delegate", "scan", "native"], default="delegate", help="执行模式 (delegate: agy委派 | scan: 纯规则扫描 | native: 原生ocr桥接)")
    p_review.add_argument("--preview", action="store_true", help="仅预览变更文件列表与噪点过滤结果")
    p_review.add_argument("--json", action="store_true", help="输出机器可读 JSON 格式")
    p_review.add_argument("--strict", action="store_true", help="严格模式（命中任何问题以退出码 1 退出）")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "audit-test":
        return cmd_audit_test(args)
    elif args.command == "run":
        return cmd_run(args)
    elif args.command == "review":
        return cmd_review(args)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
