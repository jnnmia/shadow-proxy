#!/usr/bin/env python3
"""test-adversary 自身自动化测试套件。

验证 adversary_runner.py 的 scan、audit-test、run 以及 review 确定性流水线与委派模式。
"""

import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# 引入 adversary_runner 模块
CURRENT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = CURRENT_DIR.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import adversary_runner
from adversary_runner import (
    DiffParser,
    FileNoiseFilter,
    IndustrialRuleset,
    DelegationPackager,
    FileDiff,
    DiffHunk,
    DiffLine,
    Finding,
)


class TestAdversaryRunner(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_adversary_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --- 1. scan 与 audit-test 基础测试 ---

    def test_scan_detects_swallowed_exception(self):
        """测试 scan 能够准确识别 except Exception: pass 风险。"""
        bad_code = self.test_dir / "bad_code.py"
        bad_code.write_text("try:\n    do_something()\nexcept Exception:\n    pass\n", encoding="utf-8")

        findings = []
        adversary_runner.scan_code_file(bad_code, findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ADV-CODE-002")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_scan_detects_unsafe_exec(self):
        """测试 scan 能够准确识别 exec/eval 风险。"""
        eval_code = self.test_dir / "eval_code.py"
        eval_code.write_text("user_input = '__import__(\"os\")'\neval(user_input)\n", encoding="utf-8")

        findings = []
        adversary_runner.scan_code_file(eval_code, findings)
        self.assertTrue(any(f.rule_id == "ADV-CODE-001" for f in findings))

    def test_audit_test_detects_assertion_free_test(self):
        """测试 audit-test 能够准确识别无断言的假绿灯测试用例。"""
        ghost_test = self.test_dir / "test_ghost.py"
        ghost_test.write_text(
            "import unittest\n\n"
            "class DummyTest(unittest.TestCase):\n"
            "    def test_nothing(self):\n"
            "        x = 1 + 1\n",
            encoding="utf-8",
        )

        findings = []
        adversary_runner.audit_test_file(ghost_test, findings)
        self.assertTrue(any(f.rule_id == "ADV-TEST-003" for f in findings))

    def test_audit_test_detects_constant_true_assert(self):
        """测试 audit-test 能够准确识别 assert True 恒真假断言。"""
        fake_test = self.test_dir / "test_fake.py"
        fake_test.write_text(
            "import unittest\n\n"
            "class FakeTest(unittest.TestCase):\n"
            "    def test_true(self):\n"
            "        assert True\n",
            encoding="utf-8",
        )

        findings = []
        adversary_runner.audit_test_file(fake_test, findings)
        self.assertTrue(any(f.rule_id == "ADV-TEST-001" for f in findings))

    def test_cli_exit_code_on_clean_dir(self):
        """测试干净目录的 CLI scan 返回 EXIT_OK (0)。"""
        clean_code = self.test_dir / "clean.py"
        clean_code.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        exit_code = adversary_runner.main(["scan", "--dir", str(self.test_dir), "--mode", "code"])
        self.assertEqual(exit_code, 0)

    def test_cli_exit_code_on_vulnerable_code(self):
        """测试发现高危漏洞时 CLI scan 返回 EXIT_DEFECT (1)。"""
        vuln_code = self.test_dir / "vuln.py"
        vuln_code.write_text("eval('1+1')\n", encoding="utf-8")

        exit_code = adversary_runner.main(["scan", "--dir", str(self.test_dir), "--mode", "code"])
        self.assertEqual(exit_code, 1)

    # --- 2. 确定性 Diff 解析与噪点过滤测试 ---

    def test_noise_filter(self):
        """测试噪点过滤器能够精准过滤 lock 文件、编译产物与二进制文件。"""
        self.assertTrue(FileNoiseFilter.is_noise("package-lock.json"))
        self.assertTrue(FileNoiseFilter.is_noise("pnpm-lock.yaml"))
        self.assertTrue(FileNoiseFilter.is_noise("Cargo.lock"))
        self.assertTrue(FileNoiseFilter.is_noise("dist/bundle.js"))
        self.assertTrue(FileNoiseFilter.is_noise("build/output.min.js"))
        self.assertTrue(FileNoiseFilter.is_noise("assets/logo.png"))
        self.assertTrue(FileNoiseFilter.is_noise("node_modules/express/index.js"))
        self.assertTrue(FileNoiseFilter.is_noise("proto/service.pb.go"))

        self.assertFalse(FileNoiseFilter.is_noise("src/auth.py"))
        self.assertFalse(FileNoiseFilter.is_noise("pkg/pool.go"))
        self.assertFalse(FileNoiseFilter.is_noise("service/UserService.java"))
        self.assertFalse(FileNoiseFilter.is_noise("components/Header.tsx"))

    def test_diff_parser_exact_line_numbers(self):
        """测试 Unified Diff 解析器计算确切的新旧行号，杜绝行号漂移。"""
        sample_diff = (
            "diff --git a/app.py b/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -10,4 +10,5 @@ def run():\n"
            " context_before\n"
            "-old_line\n"
            "+new_line_1\n"
            "+new_line_2\n"
            " context_after\n"
        )
        files = DiffParser.parse(sample_diff)
        self.assertEqual(len(files), 1)
        file_diff = files[0]
        self.assertEqual(file_diff.path, "app.py")
        self.assertEqual(len(file_diff.hunks), 1)
        hunk = file_diff.hunks[0]

        lines = hunk.lines
        self.assertEqual(len(lines), 5)
        # 1. context_before: old 10, new 10
        self.assertEqual(lines[0].line_type, " ")
        self.assertEqual(lines[0].old_lineno, 10)
        self.assertEqual(lines[0].new_lineno, 10)

        # 2. -old_line: old 11, new None
        self.assertEqual(lines[1].line_type, "-")
        self.assertEqual(lines[1].old_lineno, 11)
        self.assertIsNone(lines[1].new_lineno)

        # 3. +new_line_1: old None, new 11
        self.assertEqual(lines[2].line_type, "+")
        self.assertIsNone(lines[2].old_lineno)
        self.assertEqual(lines[2].new_lineno, 11)

        # 4. +new_line_2: old None, new 12
        self.assertEqual(lines[3].line_type, "+")
        self.assertIsNone(lines[3].old_lineno)
        self.assertEqual(lines[3].new_lineno, 12)

        # 5. context_after: old 12, new 13
        self.assertEqual(lines[4].line_type, " ")
        self.assertEqual(lines[4].old_lineno, 12)
        self.assertEqual(lines[4].new_lineno, 13)

    # --- 3. 工业级多语言规则命中测试 ---

    def test_industrial_ruleset_detects_go_npe_and_goroutine(self):
        """测试 Go 语言规则：未判空错误解引用与协程泄漏。"""
        go_diff = (
            "diff --git a/worker.go b/worker.go\n"
            "--- a/worker.go\n"
            "+++ b/worker.go\n"
            "@@ -20,4 +20,6 @@ func Handle() {\n"
            "+    res, err := client.Do()\n"
            "+    name := res.Header\n"
            "+    go func() {\n"
            "+        process()\n"
            "+    }()\n"
            " }\n"
        )
        files = DiffParser.parse(go_diff)
        findings = IndustrialRuleset.check_file_diff(files[0])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE-NPE-GO-001", rule_ids)
        self.assertIn("RULE-CONC-GO-001", rule_ids)

    def test_industrial_ruleset_detects_java_npe_and_concurrency(self):
        """测试 Java 规则：Map.get() 裸链式调用与非线程安全成员变量。"""
        java_diff = (
            "diff --git a/Service.java b/Service.java\n"
            "--- a/Service.java\n"
            "+++ b/Service.java\n"
            "@@ -10,3 +10,4 @@ public class Service {\n"
            "+    private SimpleDateFormat sdf = new SimpleDateFormat();\n"
            "+    String role = userMap.get(id).getRole();\n"
            " }\n"
        )
        files = DiffParser.parse(java_diff)
        findings = IndustrialRuleset.check_file_diff(files[0])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE-NPE-JAVA-001", rule_ids)
        self.assertIn("RULE-CONC-JAVA-001", rule_ids)

    def test_industrial_ruleset_detects_ts_npe_and_xss(self):
        """测试 TS 规则：深层对象解构缺失可选链与 XSS 注入。"""
        ts_diff = (
            "diff --git a/comp.tsx b/comp.tsx\n"
            "--- a/comp.tsx\n"
            "+++ b/comp.tsx\n"
            "@@ -5,3 +5,4 @@ export const Comp = () => {\n"
            "+    const email = req.body.user.profile.email;\n"
            "+    return <div dangerouslySetInnerHTML={{ __html: rawContent }} />;\n"
            " }\n"
        )
        files = DiffParser.parse(ts_diff)
        findings = IndustrialRuleset.check_file_diff(files[0])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE-NPE-TS-001", rule_ids)
        self.assertIn("RULE-SEC-XSS-001", rule_ids)

    def test_industrial_ruleset_detects_sqli_and_path_traversal(self):
        """测试通用安全规则：SQL 注入拼接与路径穿越。"""
        py_diff = (
            "diff --git a/db.py b/db.py\n"
            "--- a/db.py\n"
            "+++ b/db.py\n"
            "@@ -1,3 +1,4 @@\n"
            "+cursor.execute(f\"SELECT * FROM users WHERE name = '{user_name}'\")\n"
            "+target = os.path.join(base_dir, user_input)\n"
        )
        files = DiffParser.parse(py_diff)
        findings = IndustrialRuleset.check_file_diff(files[0])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE-SEC-SQLI-001", rule_ids)
        self.assertIn("RULE-SEC-TRAV-001", rule_ids)

    # --- 4. 委派模式组包与 CLI 审查端到端测试 ---

    def test_delegation_packager(self):
        """测试委派组包器构建结构完整且行号准确的上下文包。"""
        sample_diff = (
            "diff --git a/vuln.py b/vuln.py\n"
            "--- a/vuln.py\n"
            "+++ b/vuln.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+f = open('data.txt')\n"
            "+cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n"
        )
        files = DiffParser.parse(sample_diff)
        findings = IndustrialRuleset.check_file_diff(files[0])

        package = DelegationPackager.build_package(
            target_desc="test diff",
            reviewable_files=files,
            noise_files=[],
            findings=findings,
        )

        self.assertIn("summary", package)
        self.assertIn("delegation_prompt", package)
        self.assertEqual(package["summary"]["files_scanned"], 1)
        self.assertGreaterEqual(package["summary"]["candidate_rule_hits"], 1)
        self.assertIn("RULE-SEC-SQLI-001", package["delegation_prompt"])

    def test_cli_review_preview_with_diff_file(self):
        """测试 CLI review --preview --diff-file 输出准确预览并以 0 退出。"""
        diff_file = self.test_dir / "sample.diff"
        diff_file.write_text(
            "diff --git a/package-lock.json b/package-lock.json\n"
            "--- a/package-lock.json\n"
            "+++ b/package-lock.json\n"
            "@@ -1,2 +1,2 @@\n"
            "-lock1\n"
            "+lock2\n"
            "diff --git a/main.py b/main.py\n"
            "--- a/main.py\n"
            "+++ b/main.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+print('hello')\n",
            encoding="utf-8",
        )

        exit_code = adversary_runner.main([
            "review",
            "--diff-file", str(diff_file),
            "--preview",
            "--json",
        ])
        self.assertEqual(exit_code, 0)

    def test_cli_review_scan_strict_detects_defect(self):
        """测试 CLI review --mode scan --strict 命中高危漏洞时返回 EXIT_DEFECT (1)。"""
        diff_file = self.test_dir / "sqli.diff"
        diff_file.write_text(
            "diff --git a/query.py b/query.py\n"
            "--- a/query.py\n"
            "+++ b/query.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+cursor.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")\n",
            encoding="utf-8",
        )

        exit_code = adversary_runner.main([
            "review",
            "--diff-file", str(diff_file),
            "--mode", "scan",
            "--strict",
        ])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
