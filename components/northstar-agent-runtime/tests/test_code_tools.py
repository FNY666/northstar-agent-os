from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import ToolContext, ToolSandbox, build_code_registry, build_default_registry
from code_task import CodePhaseMachine


def git(root: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process.stdout


class CodeToolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init")
        git(self.root, "config", "user.email", "northstar-tests@example.invalid")
        git(self.root, "config", "user.name", "Northstar Tests")
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        (self.root / "README.md").write_text("# Example\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "initial")
        self.registry = build_code_registry()
        config = SimpleNamespace(
            verification_commands=("printf 42",),
        )
        self.phases = CodePhaseMachine(
            run_id="code-tools-test",
            evidence_dir=self.root,
        )
        self.phases.start()
        self.context = ToolContext(
            session_id="code-tools-test",
            sandbox=ToolSandbox(self.root),
            services={
                "registry": self.registry,
                "config": config,
                "code_phase_machine": self.phases,
                "shell_backend": "process",
                "shell_seccomp": "off",
                "shell_capdrop": "off",
                "shell_landlock": "off",
                "shell_aggregate_resource_scope": "off",
            },
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_code_profile_does_not_change_kernel_registry(self):
        self.assertNotIn("RepoMap", build_default_registry().names())
        self.assertEqual(
            {"RepoMap", "SearchCode", "GitInspect", "SubmitPlan", "ApplyPatch", "RunCheck"},
            set(self.registry.names()) - set(build_default_registry().names()),
        )

    def test_submit_plan_advances_the_host_phase_once(self):
        payload = {
            "summary": "update the implementation",
            "files": ["src/app.py"],
            "steps": ["change the return value"],
            "risks": [],
            "check_indices": [0],
        }
        accepted = self.registry.require("SubmitPlan").handler(payload, self.context)
        self.assertFalse(accepted.is_error, accepted.text())
        self.assertEqual(self.phases.state, "planned")
        refused = self.registry.require("SubmitPlan").handler(payload, self.context)
        self.assertTrue(refused.is_error)

    def test_repo_map_and_literal_search_are_bounded_repository_views(self):
        (self.root / "ignored.txt").write_text("needle[0]\n", encoding="utf-8")
        mapped = self.registry.require("RepoMap").handler({"max_files": 10}, self.context)
        self.assertFalse(mapped.is_error, mapped.text())
        self.assertIn("README.md", mapped.text())
        self.assertIn("src/app.py", mapped.text())
        self.assertNotIn("ignored.txt", mapped.text())

        (self.root / "src" / "app.py").write_text("needle[0]\nneedle0\n", encoding="utf-8")
        searched = self.registry.require("SearchCode").handler(
            {"query": "needle[0]", "glob": "**/*.py"}, self.context
        )
        self.assertEqual(searched.data["matches"], 1)
        self.assertIn("needle[0]", searched.text())

    def test_apply_patch_and_git_inspect_show_the_change(self):
        patch = """diff --git a/src/app.py b/src/app.py
index 760a15b..87de0d4 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,2 @@
 def value():
-    return 1
+    return 2
"""
        applied = self.registry.require("ApplyPatch").handler({"patch": patch}, self.context)
        self.assertFalse(applied.is_error, applied.text())
        self.assertIn("return 2", (self.root / "src" / "app.py").read_text(encoding="utf-8"))
        inspected = self.registry.require("GitInspect").handler(
            {"action": "diff", "path": "src/app.py"}, self.context
        )
        self.assertFalse(inspected.is_error, inspected.text())
        self.assertIn("+    return 2", inspected.text())

    def test_apply_patch_cannot_modify_governance_paths(self):
        (self.root / ".northstar").mkdir()
        (self.root / ".northstar" / "config.toml").write_text("mode='default'\n", encoding="utf-8")
        patch = """diff --git a/.northstar/config.toml b/.northstar/config.toml
--- a/.northstar/config.toml
+++ b/.northstar/config.toml
@@ -1 +1 @@
-mode='default'
+mode='bypassPermissions'
"""
        refused = self.registry.require("ApplyPatch").handler({"patch": patch}, self.context)
        self.assertTrue(refused.is_error)
        self.assertIn("patch refused", refused.text())
        self.assertEqual(
            (self.root / ".northstar" / "config.toml").read_text(encoding="utf-8"),
            "mode='default'\n",
        )

    def test_apply_patch_rejects_an_extra_file_section_hidden_after_safe_header(self):
        (self.root / ".northstar").mkdir()
        (self.root / ".northstar" / "config.toml").write_text("mode='default'\n", encoding="utf-8")
        patch = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,2 @@
 def value():
-    return 1
+    return 2
--- a/.northstar/config.toml
+++ b/.northstar/config.toml
@@ -1 +1 @@
-mode='default'
+mode='bypassPermissions'
"""
        refused = self.registry.require("ApplyPatch").handler({"patch": patch}, self.context)
        self.assertTrue(refused.is_error)
        self.assertEqual(
            (self.root / "src" / "app.py").read_text(encoding="utf-8"),
            "def value():\n    return 1\n",
        )
        self.assertEqual(
            (self.root / ".northstar" / "config.toml").read_text(encoding="utf-8"),
            "mode='default'\n",
        )

    def test_run_check_uses_only_the_host_declared_index(self):
        refused = self.registry.require("RunCheck").handler({"index": 1}, self.context)
        self.assertTrue(refused.is_error)
        result = self.registry.require("RunCheck").handler({"index": 0}, self.context)
        self.assertFalse(result.is_error, result.text())
        self.assertTrue(result.data["ok"])
        self.assertEqual(result.data["exit_code"], 0)
        self.assertIn("42", result.text())


if __name__ == "__main__":
    unittest.main()
