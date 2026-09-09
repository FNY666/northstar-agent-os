"""Workspace-scoped memory + skill scripts (P4). No global MEMORY."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from support import RuntimeTestCase, tool_turn

from memory import (
    MEMORY_DIRECTORY,
    MemoryError,
    append_memory,
    default_memory_path,
    digest_text,
    discover_memory,
    is_memory_write_path,
)
from tools import ToolAccessError, ToolSandbox, build_default_registry, write_file, ToolContext, ToolLimits
from tools.skill_scripts import discover_skill_scripts, skill_scripts_listing
from skills import discover_skills


def run_cli(*argv: str) -> tuple[int, str, str]:
    import contextlib
    import io
    import sys

    from cli import main

    out, err = io.StringIO(), io.StringIO()
    saved, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved
    return code, out.getvalue(), err.getvalue()


class MemoryUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nsar-mem-"))
        (self.root / MEMORY_DIRECTORY).mkdir(parents=True)
        self.mem = default_memory_path(self.root)
        self.mem.write_text("# Notes\n\nRemember the fixture path.\n", encoding="utf-8")

    def test_discover_loads_default_with_digest(self):
        memory = discover_memory(self.root)
        self.assertIsNotNone(memory)
        assert memory is not None
        self.assertIn("Remember the fixture", memory.text)
        self.assertEqual(memory.digest, digest_text(memory.text))
        self.assertTrue(memory.relative.endswith("MEMORY.md"))

    def test_append_labels_digest_and_workspace_scope(self):
        memory = discover_memory(self.root)
        assert memory is not None
        prompt = append_memory("BASE", memory)
        self.assertIn("BASE", prompt)
        self.assertIn("Workspace memory", prompt)
        self.assertIn(memory.digest[:12], prompt)
        self.assertIn("never a global MEMORY", prompt)
        self.assertIn("End of workspace memory", prompt)

    def test_disabled_returns_none(self):
        self.assertIsNone(discover_memory(self.root, configured=False))

    def test_missing_file_is_none_not_error(self):
        empty = Path(tempfile.mkdtemp(prefix="nsar-mem-empty-"))
        self.assertIsNone(discover_memory(empty))

    def test_symlink_escape_is_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-mem-out-"))
        target = outside / "leak.md"
        target.write_text("secret", encoding="utf-8")
        link = self.root / "escape.md"
        link.symlink_to(target)
        with self.assertRaises(MemoryError):
            discover_memory(self.root, explicit=str(link))

    def test_is_memory_write_path_only_under_carve_out(self):
        self.assertTrue(is_memory_write_path((".northstar", "memory", "MEMORY.md")))
        self.assertTrue(is_memory_write_path((".northstar", "memory", "notes", "a.md")))
        self.assertFalse(is_memory_write_path((".northstar", "config.toml")))
        self.assertFalse(is_memory_write_path((".northstar", "skills", "x", "SKILL.md")))
        self.assertFalse(is_memory_write_path(("notes.txt",)))


class MemorySandboxTests(RuntimeTestCase):
    def test_write_to_memory_is_allowed_without_policy_override(self):
        root = self.workspace()
        (root / MEMORY_DIRECTORY).mkdir(parents=True)
        sandbox = ToolSandbox(root)  # default protected_prefixes includes .northstar
        ctx = ToolContext(session_id="t", sandbox=sandbox, limits=ToolLimits())
        result = write_file({"path": f"{MEMORY_DIRECTORY}/MEMORY.md", "content": "hello memory\n"}, ctx)
        self.assertFalse(result.is_error, result.content)
        self.assertEqual((root / MEMORY_DIRECTORY / "MEMORY.md").read_text(encoding="utf-8"), "hello memory\n")

    def test_write_to_policy_still_refused(self):
        root = self.workspace()
        (root / ".northstar").mkdir()
        sandbox = ToolSandbox(root)
        ctx = ToolContext(session_id="t", sandbox=sandbox, limits=ToolLimits())
        with self.assertRaises(ToolAccessError) as caught:
            sandbox.resolve(".northstar/config.toml", for_write=True)
        self.assertIn("governance", str(caught.exception).lower())


class MemoryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-mem-cli-"))
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        (self.workspace / MEMORY_DIRECTORY).mkdir(parents=True)
        (self.workspace / MEMORY_DIRECTORY / "MEMORY.md").write_text(
            "Prefer short answers.\n", encoding="utf-8"
        )

    def test_dry_run_reports_memory_digest(self):
        code, out, err = run_cli(
            "run",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "hi",
            "--scripted-text",
            "ok",
            "--dry-run",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("memory=", out)
        self.assertIn("MEMORY.md", out)
        self.assertIn("digest=", out)

    def test_no_memory_opts_out(self):
        code, out, err = run_cli(
            "run",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "hi",
            "--scripted-text",
            "ok",
            "--no-memory",
            "--dry-run",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("memory=off (--no-memory)", out)

    def test_agent_injects_memory_into_the_run(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "hi",
            "--scripted-text",
            "remembered",
            "--json",
        )
        self.assertEqual(code, 0, err)
        # System prompt is not dumped in events by default; the dry-run line is the
        # operator-facing proof. Also assert the Write carve-out via a scripted tool.
        script = self.workspace / "s.json"
        script.write_text(
            json.dumps(
                [
                    {
                        "tool": {
                            "name": "Write",
                            "input": {
                                "path": f"{MEMORY_DIRECTORY}/MEMORY.md",
                                "content": "updated by agent\n",
                            },
                        }
                    },
                    {"text": "saved"},
                ]
            ),
            encoding="utf-8",
        )
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "update memory",
            "--script",
            str(script),
            "--allow-tool",
            "Write",
            "--json",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            (self.workspace / MEMORY_DIRECTORY / "MEMORY.md").read_text(encoding="utf-8"),
            "updated by agent\n",
        )


class SkillScriptTests(RuntimeTestCase):
    def test_discover_lists_scripts_under_skill(self):
        root = self.workspace()
        skill_dir = root / ".northstar" / "skills" / "demo"
        scripts = skill_dir / "scripts"
        scripts.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo\ndescription: Demo skill with a helper script.\n---\n\nUse the script.\n",
            encoding="utf-8",
        )
        (scripts / "helper.py").write_text("print('hi')\n", encoding="utf-8")
        (scripts / "notes.txt").write_text("not a script\n", encoding="utf-8")
        skills = discover_skills(root)
        found = discover_skill_scripts(root, skills)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].skill, "demo")
        self.assertEqual(found[0].name, "helper.py")
        self.assertIn("scripts/helper.py", found[0].relative)
        listing = skill_scripts_listing(found)
        self.assertIn("helper.py", listing)
        self.assertIn("--allow-tool Shell", listing)
        self.assertIn("Skill scripts", listing)

    def test_cli_lists_skill_scripts_in_prompt_path(self):
        root = Path(tempfile.mkdtemp(prefix="nsar-ss-"))
        skill_dir = root / ".northstar" / "skills" / "pack"
        scripts = skill_dir / "scripts"
        scripts.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: pack\ndescription: Pack with script.\n---\n\nBody.\n",
            encoding="utf-8",
        )
        (scripts / "run.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        code, out, err = run_cli(
            "run",
            "--workspace",
            str(root),
            "--prompt",
            "hi",
            "--scripted-text",
            "ok",
            "--dry-run",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("skills=", out)
        self.assertIn("pack", out)


if __name__ == "__main__":
    unittest.main()
