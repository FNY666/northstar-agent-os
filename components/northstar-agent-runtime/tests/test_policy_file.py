"""Workspace policy file (``.northstar/config.toml``) and project context (``AGENTS.md``).

The rules under test are the governance contract:

- A policy file may only *tighten*: no bypass/acceptEdits mode, no allow list,
  ceilings at or below the built-in defaults, denials additive. Violations are
  configuration errors (the CLI exits 64), never silent ignores.
- File denials and ``read_only`` are a floor: even an explicit ``--allow-tool``
  cannot resurrect a file-denied tool, because the permission gate's first
  layer keeps denials terminal.
- Ceilings are the lower of CLI/file when both are set.
- Project context is discovered strictly inside the workspace root; a symlink
  or ``--context-file`` pointing outside is refused, never followed.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import cli
from cli import USAGE_ERROR, build_parser, main
from policy_file import (
    CONTEXT_MAX_CHARS,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TURNS,
    PolicyFileError,
    ProjectContext,
    append_project_context,
    discover_project_context,
    load_policy_file,
    policy_file_path,
)
import policy_file


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


def write_policy(workspace: Path, text: str) -> Path:
    directory = workspace / ".northstar"
    directory.mkdir(exist_ok=True)
    path = directory / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


class PolicyFileLoadTests(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-policy-"))
        self.known_tools = ("Read", "Grep", "LS", "Write", "Edit", "DescribeTools", "Task")
        self.known_agents = ("evaluator", "explorer", "planner", "general")

    def load(self):
        return load_policy_file(self.ws, known_tools=self.known_tools, known_agents=self.known_agents)

    def test_absent_file_means_no_policy(self):
        self.assertIsNone(self.load())

    def test_a_valid_policy_file_parses(self):
        write_policy(self.ws, 'deny_tools = ["Write"]\nmax_turns = 10\nmax_budget_usd = 0.25\n')
        policy = self.load()
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy.deny_tools, ("Write",))
        self.assertEqual(policy.max_turns, 10)
        self.assertEqual(policy.max_budget_usd, 0.25)
        self.assertEqual(policy.project_context_setting, "AGENTS.md")

    def test_an_unknown_key_is_a_configuration_error(self):
        write_policy(self.ws, 'loosen_tools = ["Write"]\n')
        with self.assertRaises(PolicyFileError) as caught:
            self.load()
        self.assertIn("unknown key", str(caught.exception))
        self.assertIn("loosen_tools", str(caught.exception))

    def test_bypass_and_accept_edits_modes_are_rejected_in_a_file(self):
        for mode in ("bypassPermissions", "acceptEdits"):
            write_policy(self.ws, f'permission_mode = "{mode}"\n')
            with self.assertRaises(PolicyFileError) as caught:
                self.load()
            self.assertIn("may only tighten", str(caught.exception))

    def test_plan_and_default_modes_are_allowed(self):
        for mode in ("plan", "default"):
            write_policy(self.ws, f'permission_mode = "{mode}"\n')
            self.assertIsNotNone(self.load())

    def test_allow_tools_is_rejected_in_a_file(self):
        write_policy(self.ws, 'allow_tools = ["Read"]\n')
        with self.assertRaises(PolicyFileError):
            self.load()
        write_policy(self.ws, 'allow_tools = []\n')
        self.assertIsNotNone(self.load())

    def test_ceilings_may_only_lower(self):
        write_policy(self.ws, f"max_turns = {DEFAULT_MAX_TURNS + 1}\n")
        with self.assertRaises(PolicyFileError):
            self.load()
        write_policy(self.ws, f"max_tool_calls = {DEFAULT_MAX_TOOL_CALLS + 1}\n")
        with self.assertRaises(PolicyFileError):
            self.load()
        write_policy(self.ws, "max_turns = 0\n")
        with self.assertRaises(PolicyFileError):
            self.load()
        write_policy(self.ws, "max_budget_usd = 0\n")
        with self.assertRaises(PolicyFileError):
            self.load()

    def test_unknown_deny_and_unknown_agent_are_configuration_errors(self):
        write_policy(self.ws, 'deny_tools = ["NoSuchTool"]\n')
        with self.assertRaises(PolicyFileError) as caught:
            self.load()
        self.assertIn("NoSuchTool", str(caught.exception))
        write_policy(self.ws, 'deny_tools = ["Write"]\nagent = "no-such-agent"\n')
        with self.assertRaises(PolicyFileError) as caught:
            self.load()
        self.assertIn("no-such-agent", str(caught.exception))

    def test_forward_looking_deny_of_the_codex_tool_is_accepted(self):
        write_policy(self.ws, 'deny_tools = ["CodexReadOnly"]\n')
        self.assertIsNotNone(self.load())

    def test_bad_toml_is_a_configuration_error(self):
        write_policy(self.ws, "permission_mode = \n")
        with self.assertRaises(PolicyFileError):
            self.load()

    def test_project_context_setting_rules(self):
        write_policy(self.ws, 'project_context = "docs/CONTEXT.md"\n')
        with self.assertRaises(PolicyFileError):
            self.load()
        write_policy(self.ws, "project_context = false\n")
        self.assertFalse(self.load().project_context_setting)  # type: ignore[union-attr]
        write_policy(self.ws, 'project_context = "AGENTS.md"\n')
        self.assertEqual(self.load().project_context_setting, "AGENTS.md")  # type: ignore[union-attr]

    def test_tighten_only_limits_stay_in_sync_with_loop_defaults(self):
        import loop

        self.assertEqual(DEFAULT_MAX_TURNS, loop.DEFAULT_MAX_TURNS)
        self.assertEqual(DEFAULT_MAX_TOOL_CALLS, loop.DEFAULT_MAX_TOOL_CALLS)


class ProjectContextTests(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-context-"))

    def test_discovery_reads_agents_md_from_the_workspace_root(self):
        (self.ws / "AGENTS.md").write_text("alpha rules\n", encoding="utf-8")
        context = discover_project_context(self.ws)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.name, "AGENTS.md")
        self.assertIn("alpha rules", context.text)

    def test_no_file_means_no_context(self):
        self.assertIsNone(discover_project_context(self.ws))

    def test_configured_false_disables_discovery(self):
        (self.ws / "AGENTS.md").write_text("x\n", encoding="utf-8")
        self.assertIsNone(discover_project_context(self.ws, configured=False))

    def test_a_symlink_escaping_the_workspace_is_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-outside-")) / "secret.md"
        outside.write_text("secret\n", encoding="utf-8")
        (self.ws / "AGENTS.md").symlink_to(outside)
        with self.assertRaises(PolicyFileError) as caught:
            discover_project_context(self.ws)
        self.assertIn("outside the workspace", str(caught.exception))

    def test_explicit_context_file_must_live_inside_the_workspace(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-outside-")) / "ctx.md"
        outside.write_text("secret\n", encoding="utf-8")
        with self.assertRaises(PolicyFileError):
            discover_project_context(self.ws, explicit=outside)
        inside = self.ws / "ctx.md"
        inside.write_text("inside\n", encoding="utf-8")
        context = discover_project_context(self.ws, explicit=inside)
        self.assertEqual(context.name, "ctx.md")  # type: ignore[union-attr]
        with self.assertRaises(PolicyFileError):
            discover_project_context(self.ws, explicit=self.ws / "missing.md")

    def test_oversized_context_is_truncated_and_marked(self):
        (self.ws / "AGENTS.md").write_text("z" * (CONTEXT_MAX_CHARS + 500), encoding="utf-8")
        context = discover_project_context(self.ws)
        assert context is not None
        self.assertTrue(context.truncated)
        self.assertEqual(len(context.text), CONTEXT_MAX_CHARS)

    def test_append_marks_the_developer_authored_section(self):
        (self.ws / "AGENTS.md").write_text("repo rules", encoding="utf-8")
        context = discover_project_context(self.ws)
        assert context is not None
        prompt = append_project_context("base prompt", context)
        self.assertTrue(prompt.startswith("base prompt"))
        self.assertIn("== Project instructions (AGENTS.md) ==", prompt)
        self.assertIn("== End of project instructions ==", prompt)
        self.assertIn("repo rules", prompt)


class PolicyCliIntegrationTests(unittest.TestCase):
    """End-to-end: the CLI resolves the policy file exactly as a run would."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-clipolicy-"))

    def dry_run(self, *extra: str) -> tuple[int, str, str]:
        return run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                       "--scripted-text", "reply", "--dry-run", *extra)

    def test_mode_plan_and_ceilings_apply_without_cli_flags(self):
        write_policy(self.ws, 'permission_mode = "plan"\nmax_turns = 5\n')
        code, out, _ = self.dry_run()
        self.assertEqual(code, 0)
        self.assertIn("permission_mode=plan", out)
        self.assertIn("max_turns=5", out)
        self.assertIn("policy_file=", out)
        self.assertIn("config.toml", out)

    def test_file_deny_is_a_floor_cli_allow_cannot_resurrect(self):
        write_policy(self.ws, 'deny_tools = ["Write"]\n')
        code, out, _ = self.dry_run("--allow-tool", "Write")
        self.assertEqual(code, 0)
        self.assertIn("disallowed_tools=Write", out)
        self.assertIn("allowed_tools=(none)", out)

    def test_read_only_in_the_file_denies_the_mutating_tools(self):
        write_policy(self.ws, "read_only = true\n")
        code, out, _ = self.dry_run()
        self.assertEqual(code, 0)
        self.assertIn("disallowed_tools=Write,Edit", out)

    def test_ceilings_take_the_lower_of_cli_and_file(self):
        write_policy(self.ws, "max_turns = 5\nmax_budget_usd = 0.1\n")
        code, out, _ = self.dry_run("--max-turns", "12", "--max-budget-usd", "5")
        self.assertEqual(code, 0)
        self.assertIn("max_turns=5", out)
        self.assertIn("max_budget_usd=0.1", out)

    def test_file_halt_on_denial_ends_a_denied_run_with_exit_5(self):
        write_policy(self.ws, "halt_on_denial = true\n")
        script = self.ws / "s.json"
        script.write_text(
            json.dumps([{"tool": {"name": "Write", "input": {"path": "x", "content": "y"}}}]),
            encoding="utf-8",
        )
        code, out, _ = run_cli("run", "--workspace", str(self.ws), "--prompt", "write",
                               "--script", str(script), "--quiet")
        self.assertEqual(code, 5)
        self.assertIn("error_permission_denied", out)

    def test_file_agent_applies_and_cli_agent_wins(self):
        write_policy(self.ws, 'agent = "explorer"\n')
        code, out, _ = self.dry_run()
        self.assertEqual(code, 0)
        self.assertIn("agent 'explorer'", out)
        code, out, _ = self.dry_run("--agent", "planner")
        self.assertEqual(code, 0)
        self.assertIn("agent 'planner'", out)

    def test_loosening_files_are_configuration_errors(self):
        for toml in (
            'permission_mode = "acceptEdits"\n',
            "allow_tools = [\"Read\"]\n",
            "max_turns = 50\n",
            "loosen = true\n",
        ):
            write_policy(self.ws, toml)
            code, _, err = self.dry_run()
            self.assertEqual(code, USAGE_ERROR, toml)
            self.assertIn("configuration error", err)

    def test_no_policy_file_ignores_a_loosening_file(self):
        write_policy(self.ws, "max_turns = 99\n")
        code, out, _ = self.dry_run("--no-policy-file")
        self.assertEqual(code, 0)
        self.assertIn("permission_mode=default", out)
        self.assertIn("policy_file=none (--no-policy-file)", out)

    def test_explicit_cli_mode_beats_a_file_mode(self):
        write_policy(self.ws, 'permission_mode = "plan"\n')
        code, out, _ = self.dry_run("--permission-mode", "acceptEdits")
        self.assertEqual(code, 0)
        self.assertIn("permission_mode=acceptEdits", out)

    def test_project_context_is_reported_by_dry_run(self):
        (self.ws / "AGENTS.md").write_text("team rules\n", encoding="utf-8")
        code, out, _ = self.dry_run()
        self.assertEqual(code, 0)
        self.assertIn("project_context=AGENTS.md", out)
        code, out, _ = self.dry_run("--no-project-context")
        self.assertEqual(code, 0)
        self.assertIn("project_context=off (--no-project-context)", out)

    def test_context_file_outside_the_workspace_is_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-outside-")) / "x.md"
        outside.write_text("x", encoding="utf-8")
        code, _, err = self.dry_run("--context-file", str(outside))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("outside the workspace", err)

    def test_a_run_succeeds_with_policy_and_context_present(self):
        write_policy(self.ws, 'deny_tools = ["Edit"]\n')
        (self.ws / "AGENTS.md").write_text("rules\n", encoding="utf-8")
        code, out, err = run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                                 "--scripted-text", "ok", "--quiet")
        self.assertEqual(code, 0, err)
        self.assertIn("[success]", out)

    def test_unknown_agent_in_the_file_is_a_usage_error(self):
        write_policy(self.ws, 'agent = "no-such-agent"\n')
        code, _, err = self.dry_run()
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("unknown agent", err)

    def test_mutually_exclusive_context_flags_are_argparse_business(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["run", "--workspace", str(self.ws), "--context-file", "x", "--no-project-context"]
            )


if __name__ == "__main__":
    unittest.main()


class PolicySchemaIdentityTests(unittest.TestCase):
    """schema_version + revision: versioned policy documents (P3-1b)."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-policy-schema-"))
        self.known_tools = ("Read", "Grep", "LS", "Write", "Edit", "DescribeTools", "Task")
        self.known_agents = ("evaluator", "explorer", "planner", "general")

    def load(self, text: str):
        write_policy(self.ws, text)
        return load_policy_file(self.ws, known_tools=self.known_tools, known_agents=self.known_agents)

    def test_schema_version_is_optional_and_defaults_to_v1(self):
        policy = self.load('deny_tools = ["Write"]\n')
        self.assertEqual(policy.schema_version, "northstar.policy.v1")
        self.assertIsNone(policy.revision)

    def test_explicit_v1_and_revision_parse_and_are_carried(self):
        policy = self.load(
            'schema_version = "northstar.policy.v1"\nrevision = "2026-09-07.r3"\ndeny_tools = ["Write"]\n'
        )
        self.assertEqual(policy.schema_version, "northstar.policy.v1")
        self.assertEqual(policy.revision, "2026-09-07.r3")
        exported = policy.as_dict()
        self.assertEqual(exported["schema_version"], "northstar.policy.v1")
        self.assertEqual(exported["revision"], "2026-09-07.r3")

    def test_unsupported_future_schema_fails_closed(self):
        for version in ("northstar.policy.v2", "northstar.policy.v9"):
            with self.subTest(version=version):
                with self.assertRaises(PolicyFileError) as caught:
                    self.load(f'schema_version = "{version}"\n')
                message = str(caught.exception)
                self.assertIn("unsupported policy schema_version", message)
                self.assertIn("northstar.policy.v1", message)

    def test_schema_version_must_be_a_string(self):
        with self.assertRaises(PolicyFileError):
            self.load("schema_version = 1\n")

    def test_revision_must_be_an_audit_safe_identifier(self):
        for bad in ("two words", "has/slash", "x" * 200, ""):
            with self.subTest(revision=bad):
                with self.assertRaises(PolicyFileError):
                    self.load(f'revision = "{bad}"\n')
        with self.assertRaises(PolicyFileError):
            self.load("revision = 7\n")

    def test_dry_run_reports_the_policy_identity(self):
        write_policy(self.ws, 'revision = "ci.r42"\ndeny_tools = ["Write"]\n')
        code, out, _ = run_cli(
            "run", "--workspace", str(self.ws), "--prompt", "hi",
            "--scripted-text", "ok", "--dry-run",
        )
        self.assertEqual(code, 0)
        self.assertIn("schema=northstar.policy.v1", out)
        self.assertIn("revision=ci.r42", out)

    def test_dry_run_without_a_policy_mentions_none(self):
        code, out, _ = run_cli(
            "run", "--workspace", str(self.ws), "--prompt", "hi",
            "--scripted-text", "ok", "--dry-run",
        )
        self.assertEqual(code, 0)
        self.assertIn("policy_file=none", out)
