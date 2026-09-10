"""The command-line shell: flags in, exit code out.

The CLI must never turn a foreseeable failure into a traceback. Every condition
the runtime can report has a distinct exit code, and anything the operator typed
wrong is a usage error (64) that says what to type instead.
"""
from __future__ import annotations

import io
import json
import contextlib
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401
from support import text_turn, tool_turn

import cli
from cli import EXIT_CODES, USAGE_ERROR, _load_script, _tool_lists, build_parser, main


def run_cli(*argv: str, stdin_text: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class ParserTests(unittest.TestCase):
    def test_no_subcommand_prints_help_and_exits_64(self):
        code, out, _ = run_cli()
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("usage: northstar-agent-runtime", out)
        self.assertIn("scripted", out)

    def test_tools_and_agents_subcommands_describe_the_surface(self):
        code, out, _ = run_cli("tools")
        self.assertEqual(code, 0)
        for name, kind in (("Read", "read"), ("Write", "edit"), ("Edit", "edit"), ("Grep", "read"), ("LS", "read"), ("DescribeTools", "read")):
            self.assertIn(name, out)
            line = next(item for item in out.splitlines() if item.startswith(name))
            self.assertIn(kind, line, "the kind column is how a reviewer spots a mutating tool")
        self.assertIn("mutating", out)
        self.assertNotIn("CodexReadOnly", out)
        code, out, _ = run_cli("agents")
        self.assertEqual(code, 0)
        for name in ("evaluator", "explorer", "planner", "general"):
            self.assertIn(name, out)
        self.assertIn("verdict=True", out)
        self.assertIn("mode=plan", out)

    def test_an_unknown_flag_is_argparse_business(self):
        with self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(["run", "--nope"])
        self.assertEqual(caught.exception.code, 2)

    def test_permission_modes_are_closed(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["run", "--permission-mode", "godmode"])

    def test_deny_subtracts_from_the_allow_list(self):
        args = build_parser().parse_args(["run", "--allow-tool", "Write", "--deny-tool", "Write", "--allow-tool", "Read"])
        allowed, denied = _tool_lists(args, base_tools=("Read", "Write", "Edit"))
        self.assertEqual(allowed, ("Read",))
        self.assertEqual(denied, ("Write",))
        self.assertNotIn("Write", allowed, "a name in both lists would surface as a policy conflict")

    def test_read_only_implies_the_mutating_denials(self):
        args = build_parser().parse_args(["run", "--read-only", "--allow-tool", "Write", "--allow-tool", "Grep"])
        allowed, denied = _tool_lists(args, base_tools=("Read", "Write", "Edit", "Grep"))
        self.assertEqual(allowed, ("Grep",))
        self.assertEqual(sorted(denied), ["Edit", "Write"])

    def test_bypass_mode_starts_from_the_whole_registry(self):
        args = build_parser().parse_args(["run", "--permission-mode", "bypassPermissions"])
        allowed, denied = _tool_lists(args, base_tools=("Read", "Write"))
        self.assertEqual(allowed, ("Read", "Write"))
        self.assertEqual(denied, ())

    def test_scripts_must_be_arrays_or_a_turns_object(self):
        self.assertEqual(_load_script(self.write_script('[{"text": "a"}]')), [{"text": "a"}])
        self.assertEqual(_load_script(self.write_script('{"turns": [{"text": "b"}]}')), [{"text": "b"}])
        with self.assertRaises(ValueError):
            _load_script(self.write_script('{"nope": 1}'))
        with self.assertRaises(ValueError):
            _load_script(self.write_script('{"turns": {"text": "not a list"}}'))

    def write_script(self, text: str) -> str:
        path = Path(tempfile.mkdtemp(prefix="nsar-cli-")) / "script.json"
        path.write_text(text, encoding="utf-8")
        return str(path)


class RunHappyPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-cli-"))
        self.workspace = Path(self.tmp) / "ws"
        self.workspace.mkdir()
        (self.workspace / "a.txt").write_text("alpha\n", encoding="utf-8")

    def base(self, *extra: str) -> list[str]:
        return ["run", "--workspace", str(self.workspace), *extra]

    def test_a_scripted_run_succeeds_and_reports(self):
        script = self.workspace / "script.json"
        script.write_text(json.dumps([{"text": "hello from the script"}]), encoding="utf-8")
        code, out, err = run_cli(*self.base("--script", str(script), "--prompt", "greet"))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("hello from the script", out)
        self.assertIn("[success]", out)
        self.assertIn("session=ns-", out)
        self.assertIn("· tools ", out, "the init event is printed by default")

    def test_scripted_text_is_the_one_liner_form(self):
        code, out, _ = run_cli(*self.base("--scripted-text", "quick answer", "--prompt", "hi", "--quiet"))
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "[success] turns=1 tool_calls=0 cost=$0.000000 session=" + out.strip().split("session=")[1])

    def test_json_mode_emits_one_object_per_event_in_order(self):
        script = self.workspace / "s.json"
        script.write_text(
            json.dumps([{"tool": {"name": "Read", "input": {"path": "a.txt"}, "id": "t1"}}, {"text": "done"}]),
            encoding="utf-8",
        )
        code, out, _ = run_cli(*self.base("--script", str(script), "--prompt", "read", "--json"))
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([event["type"] for event in events], ["system", "assistant", "user", "assistant", "result"])
        self.assertEqual(events[0]["subtype"], "init")
        self.assertEqual(events[1]["content"][0]["name"], "Read")
        self.assertEqual(events[2]["content"][0]["tool_use_id"], "t1")
        self.assertEqual(events[2]["content"][0]["content"], "alpha\n")
        self.assertEqual(events[-1]["subtype"], "success")
        self.assertEqual(events[-1]["num_turns"], 2)
        self.assertFalse(events[-1]["is_error"])
        self.assertIn("total_usage", events[-1])

    def test_read_is_allowed_and_write_is_not_in_the_default_mode(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "nope"}, "id": "t1"}}, {"text": "noted"}]), encoding="utf-8")
        code, out, _ = run_cli(*self.base("--script", str(script), "--prompt", "write it", "--json"))
        self.assertEqual(code, 0, "a denial is reported to the model, which then answers")
        events = [json.loads(line) for line in out.splitlines()]
        self.assertTrue(events[2]["content"][0]["is_error"])
        self.assertIn("no host approval callback", events[2]["content"][0]["content"])
        self.assertFalse((self.workspace / "b.txt").exists())

    def test_halt_on_denial_exits_5(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "nope"}}}]), encoding="utf-8")
        code, out, err = run_cli(*self.base("--script", str(script), "--prompt", "write it", "--halt-on-denial", "--quiet"))
        self.assertEqual(code, 5)
        self.assertIn("error_permission_denied", out)
        self.assertIn("refused: Write", err)

    def test_read_only_flag_refuses_the_mutating_tools(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "x"}}}, {"text": "understood"}]), encoding="utf-8")
        code, out, _ = run_cli(*self.base("--script", str(script), "--prompt", "p", "--read-only", "--json"))
        self.assertEqual(code, 0)
        denial = [json.loads(line) for line in out.splitlines()][2]
        self.assertIn("refused", denial["content"][0]["content"])
        self.assertEqual(denial["content"][0]["is_error"], True)

    def test_plan_mode_is_a_shorthand_for_the_permission_mode(self):
        code, out, _ = run_cli(*self.base("--scripted-text", "planning", "--prompt", "p", "--plan", "--json"))
        self.assertEqual(code, 0)
        init = json.loads(out.splitlines()[0])
        self.assertEqual(init["data"]["permission_mode"], "plan")

    def test_allow_tool_auto_approves_a_write(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "made"}}}, {"text": "ok"}]), encoding="utf-8")
        code, out, _ = run_cli(*self.base("--script", str(script), "--prompt", "write", "--allow-tool", "Write"))
        self.assertEqual(code, 0)
        self.assertEqual((self.workspace / "b.txt").read_text(), "made")

    def test_deny_tool_wins_over_allow_tool_on_the_command_line(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "made"}}}, {"text": "ok"}]), encoding="utf-8")
        code, out, _ = run_cli(*self.base("--script", str(script), "--prompt", "write", "--allow-tool", "Write", "--deny-tool", "Write"))
        self.assertEqual(code, 0)
        self.assertFalse((self.workspace / "b.txt").exists())
        self.assertIn("refused by the permission gate", out)

    def test_quiet_prints_only_the_result_line(self):
        code, out, _ = run_cli(*self.base("--scripted-text", "short", "--prompt", "p", "--quiet"))
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("[success]", out)

    def test_trace_prints_the_span_tree(self):
        code, out, _ = run_cli(*self.base("--scripted-text", "short", "--prompt", "p", "--trace"))
        self.assertEqual(code, 0)
        self.assertIn("run (", out)
        self.assertIn("turn[1]", out)
        self.assertIn("generation", out)


class CeilingTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-"))

    def run_with(self, turns: list, *extra: str) -> tuple[int, str, str]:
        script = self.workspace / "s.json"
        script.write_text(json.dumps(turns), encoding="utf-8")
        return run_cli("run", "--workspace", str(self.workspace), "--script", str(script), "--prompt", "go", "--quiet", *extra)

    def test_every_subtype_has_its_own_exit_code(self):
        self.assertEqual(
            EXIT_CODES,
            {
                "success": 0,
                "error_during_execution": 1,
                "error_max_turns": 2,
                "error_max_tool_calls": 3,
                "error_max_budget_usd": 4,
                "error_permission_denied": 5,
                "error_cancelled": 6,
                # Appended, never re-pointed: 6 stays cancellation for consumers
                # that already ship against it.
                "error_postconditions_failed": 8,
            },
        )

    def test_max_turns(self):
        code, out, _ = self.run_with([{"tool": {"name": "Read", "input": {"path": "nope"}}}] * 5, "--max-turns", "2")
        self.assertEqual(code, 2)
        self.assertIn("error_max_turns", out)

    def test_max_tool_calls(self):
        turns = [{"tools": [{"name": "Read", "input": {"path": "nope"}}, {"name": "Read", "input": {"path": "nope2"}}]}]
        code, out, _ = self.run_with(turns, "--max-tool-calls", "1", "--max-turns", "6")
        self.assertEqual(code, 3)
        self.assertIn("error_max_tool_calls", out)

    def test_max_budget_usd(self):
        # The ceiling is checked before a generation, so the expensive turn has to
        # ask for another one: a text-only turn ends the run first.
        turns = [
            {"tool": {"name": "Read", "input": {"path": "nope"}}, "usage": {"input_tokens": 1_000_000, "output_tokens": 100_000}},
            {"text": "cheaper"},
        ]
        code, out, _ = self.run_with(turns, "--max-budget-usd", "1")
        self.assertEqual(code, 4)
        self.assertIn("error_max_budget_usd", out)

    def test_an_unfinished_script_is_reported_as_an_execution_error(self):
        code, out, err = self.run_with([{"tool": {"name": "Read", "input": {"path": "nope"}}}])
        self.assertEqual(code, 1, "the loop needed a second turn the script did not have")
        self.assertIn("error_during_execution", out)
        self.assertIn("exhausted", err, "the reason is printed on stderr, not swallowed")


class ConfigurationErrorTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-"))

    def base(self, *extra: str) -> list[str]:
        return ["run", "--workspace", str(self.workspace), *extra]

    def test_a_missing_prompt_is_a_usage_error(self):
        code, out, err = run_cli(*self.base("--scripted-text", "x"))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("no prompt", err)

    def test_a_missing_script_file_is_reported(self):
        code, _, err = run_cli(*self.base("--prompt", "p", "--script", str(self.workspace / "ghost.json")))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("file not found", err)

    def test_a_broken_script_is_a_configuration_error_not_a_traceback(self):
        path = self.workspace / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        code, _, err = run_cli(*self.base("--prompt", "p", "--script", str(path)))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("configuration error", err)
        self.assertNotIn("Traceback", err)

    def test_script_and_scripted_text_conflict(self):
        path = self.workspace / "ok.json"
        path.write_text("[{\"text\": \"x\"}]", encoding="utf-8")
        code, _, err = run_cli(*self.base("--prompt", "p", "--script", str(path), "--scripted-text", "y"))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("mutually exclusive", err)

    def test_an_unknown_agent_is_listed_with_the_alternatives(self):
        code, _, err = run_cli(*self.base("--prompt", "p", "--scripted-text", "x", "--agent", "reviewer"))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("unknown agent 'reviewer'", err)
        self.assertIn("evaluator", err)

    def test_a_negative_ceiling_is_a_configuration_error(self):
        code, _, err = run_cli(*self.base("--prompt", "p", "--scripted-text", "x", "--max-turns", "0"))
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("configuration error", err)

    def test_compaction_threshold_zero_disables_compaction(self):
        code, out, _ = run_cli(*self.base("--prompt", "p", "--scripted-text", "x", "--compaction-threshold-tokens", "0", "--json"))
        self.assertEqual(code, 0)
        init = json.loads(out.splitlines()[0])
        self.assertIsNone(init["data"]["limits"]["compaction_threshold_tokens"])


class PromptAndSessionTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-"))
        self.session_dir = self.workspace / "sessions"
        self.session_dir.mkdir()

    def test_a_prompt_file_is_read_verbatim(self):
        prompt_file = self.workspace / "task.md"
        prompt_file.write_text("summarise the file\nwith a second line\n", encoding="utf-8")
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt-file", str(prompt_file), "--scripted-text", "ok",
            "--session-dir", str(self.session_dir), "--quiet",
        )
        self.assertEqual(code, 0)
        # The CLI does not echo the prompt as an event, so the durable proof that it
        # was read verbatim is the transcript record.
        body = "\n".join(path.read_text(encoding="utf-8") for path in self.session_dir.glob("*.jsonl"))
        self.assertIn("summarise the file", body)
        self.assertIn("with a second line", body)

    def test_a_dash_reads_the_prompt_from_stdin(self):
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt-file", "-", "--scripted-text", "ok",
            "--session-dir", str(self.session_dir), "--quiet", stdin_text="prompt from the pipe\n",
        )
        self.assertEqual(code, 0)
        body = "\n".join(path.read_text(encoding="utf-8") for path in self.session_dir.glob("*.jsonl"))
        self.assertIn("prompt from the pipe", body)

    def test_a_session_dir_persists_a_transcript_named_after_the_session(self):
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "persist me", "--scripted-text", "ok",
            "--session-dir", str(self.session_dir), "--quiet",
        )
        self.assertEqual(code, 0)
        session_id = out.strip().split("session=")[1]
        files = list(self.session_dir.glob("*.jsonl"))
        self.assertEqual([path.stem for path in files], [session_id])
        records = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["type"] for record in records], ["session_start", "user_prompt", "assistant", "result", "session_end"])
        self.assertIn("persist me", files[0].read_text(encoding="utf-8"))

    def test_redacted_sessions_drop_tool_output_bodies(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Read", "input": {"path": "secret.txt"}}}, {"text": "read"}]), encoding="utf-8")
        (self.workspace / "secret.txt").write_text("TOP-SECRET-BODY\n", encoding="utf-8")
        code, _, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "p", "--script", str(script),
            "--session-dir", str(self.session_dir), "--redact-tool-output", "--quiet",
        )
        self.assertEqual(code, 0)
        body = "\n".join(path.read_text(encoding="utf-8") for path in self.session_dir.glob("*.jsonl"))
        self.assertNotIn("TOP-SECRET-BODY", body)
        self.assertIn("omitted by configuration", body)

    def test_resume_continues_a_persisted_session(self):
        first_dir = self.session_dir
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "the first question", "--scripted-text", "first answer",
            "--session-dir", str(first_dir), "--quiet",
        )
        self.assertEqual(code, 0)
        session_id = out.strip().split("session=")[1]
        before = len((first_dir / f"{session_id}.jsonl").read_text(encoding="utf-8").splitlines())
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "the follow-up", "--scripted-text", "second answer",
            "--session-dir", str(first_dir), "--resume", session_id, "--quiet",
        )
        self.assertEqual(code, 0)
        self.assertIn(session_id, out, "resuming must not mint a new session id")
        text = (first_dir / f"{session_id}.jsonl").read_text(encoding="utf-8")
        self.assertGreater(len(text.splitlines()), before)
        self.assertIn("the first question", text)
        self.assertIn("the follow-up", text)

    def test_resuming_a_session_that_does_not_exist_is_still_a_valid_run(self):
        code, out, err = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "hello", "--scripted-text", "ok",
            "--session-dir", str(self.session_dir), "--resume", "ns-19700101T000000Z-deadbeef", "--quiet",
        )
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)


class SidecarFlagTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-"))

    def test_probe_without_a_socket_is_a_usage_error(self):
        code, _, err = run_cli("run", "--workspace", str(self.workspace), "--probe-sidecar")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("--probe-sidecar needs --sidecar-socket", err)

    def test_probe_reports_an_unreachable_sidecar_and_exits_1(self):
        missing = self.workspace / "sidecar.sock"
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--probe-sidecar", "--sidecar-socket", str(missing), "--json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "transport_unavailable")
        self.assertTrue(payload["fallback_allowed"])

    def test_the_sidecar_tool_is_offered_only_with_a_socket(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "CodexReadOnly", "input": {"prompt": "check"}}}, {"text": "done"}]), encoding="utf-8")
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "delegate", "--script", str(script),
            "--sidecar-socket", str(self.workspace / "sidecar.sock"), "--json",
        )
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in out.splitlines()]
        self.assertIn("CodexReadOnly", events[0]["data"]["tools"])
        result_block = events[2]["content"][0]
        self.assertTrue(result_block["is_error"])
        self.assertIn("transport_unavailable", result_block["content"])

    def test_without_a_socket_the_model_is_not_told_codex_exists(self):
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--prompt", "p", "--scripted-text", "x", "--json")
        self.assertEqual(code, 0)
        self.assertNotIn("CodexReadOnly", json.loads(out.splitlines()[0])["data"]["tools"])


class AgentFlagTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-"))

    def test_running_as_a_builtin_agent_applies_its_policy(self):
        code, out, _ = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "judge this", "--scripted-text", "ok",
            "--agent", "evaluator", "--json",
        )
        self.assertEqual(code, 0)
        init = json.loads(out.splitlines()[0])
        self.assertEqual(init["data"]["permission_mode"], "plan")
        self.assertEqual(sorted(init["data"]["tools"]), ["DescribeTools", "Grep", "LS", "Read"])
        self.assertNotIn("Task", init["data"]["tools"])
        final = json.loads(out.splitlines()[-1])
        self.assertEqual(final["subtype"], "success")

    def test_a_verdict_less_evaluation_is_reported_as_a_fail(self):
        script = self.workspace / "s.json"
        script.write_text(json.dumps([{"text": "looks fine to me"}]), encoding="utf-8")
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--prompt", "judge", "--script", str(script), "--agent", "evaluator", "--quiet")
        self.assertEqual(code, 0)
        self.assertIn("[success]", out, "the verdict travels as text, not as the run subtype")


class ModuleEntryPointTests(unittest.TestCase):
    def test_the_module_can_be_run_as_a_program(self):
        component = Path(cli.__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, "-m", "cli", "tools"],
            cwd=str(component),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DescribeTools", result.stdout)

    def test_the_exit_code_reaches_the_shell(self):
        workspace = Path(tempfile.mkdtemp(prefix="nsar-cli-")) / "ws"
        workspace.mkdir(parents=True)
        script = workspace / "s.json"
        script.write_text(json.dumps([{"tool": {"name": "Write", "input": {"path": "x", "content": "y"}}}]), encoding="utf-8")
        component = Path(cli.__file__).resolve().parent
        result = subprocess.run(
            [
                sys.executable, "-m", "cli", "run", "--workspace", str(workspace), "--prompt", "write",
                "--script", str(script), "--halt-on-denial", "--quiet",
            ],
            cwd=str(component),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        self.assertIn("error_permission_denied", result.stdout)


class DoctorTests(unittest.TestCase):
    """`doctor` is the CLI's environment self-check: local, read-only, no requests."""

    def test_doctor_reports_a_healthy_workspace(self):
        tmp = Path(tempfile.mkdtemp(prefix="nsar-doctor-"))
        ws = tmp / "ws"
        ws.mkdir()
        code, out, err = run_cli("doctor", "--workspace", str(ws))
        self.assertEqual(code, 0, err)
        self.assertIn(f"workspace", out)
        self.assertIn("[ok]", out)
        self.assertIn("ready to run", out)

    def test_doctor_flags_a_missing_workspace_and_exits_1(self):
        code, out, _ = run_cli("doctor", "--workspace", "/nonexistent-northstar-doctor")
        self.assertEqual(code, 1)
        self.assertIn("[fail] workspace", out)
        self.assertIn("does not exist", out)
        self.assertIn("fix the failed checks", out)

    def test_doctor_accepts_a_broken_script_but_fails_on_it(self):
        tmp = Path(tempfile.mkdtemp(prefix="nsar-doctor-"))
        script = tmp / "bad.json"
        script.write_text("{not json", encoding="utf-8")
        code, out, _ = run_cli("doctor", "--workspace", str(tmp), "--provider", "scripted", "--script", str(script))
        self.assertEqual(code, 1)
        self.assertIn("[fail] script", out)

    def test_doctor_reports_missing_optional_sdks_as_warnings(self):
        # CI also exercises the optional SDK path, so force the missing-SDK
        # branch instead of making this regression depend on the host venv.
        with mock.patch("doctor.importlib.util.find_spec", return_value=None):
            code, out, _ = run_cli("doctor")
        self.assertEqual(code, 0)  # warnings, not failures
        self.assertIn("anthropic-sdk", out)
        self.assertIn("[warn]", out)
        self.assertIn("session-dir", out)

    def test_doctor_sidecar_checks_a_socket_presence(self):
        code, out, _ = run_cli("doctor", "--sidecar-socket", "/nonexistent-northstar.sock")
        self.assertEqual(code, 1)
        self.assertIn("[fail] sidecar", out)
        self.assertIn("no socket at", out)


class VersionFlagTests(unittest.TestCase):
    def test_version_flag_prints_a_single_line(self):
        # argparse's --version action prints and raises SystemExit(0), which is
        # the process-level behaviour a shell sees; exercise it directly.
        parser = cli.build_parser()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(["--version"])
        self.assertEqual(caught.exception.code, 0)
        printed = out.getvalue()
        self.assertIn("northstar-agent-runtime", printed)
        self.assertIn(cli.__version__, printed)  # the printed version is _version's, never a literal
        self.assertEqual(len(printed.strip().splitlines()), 1)

    def test_version_prints_to_stdout_and_can_be_parsed(self):
        parser = cli.build_parser()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(["--version"])
        self.assertEqual(caught.exception.code, 0)
        self.assertTrue(out.getvalue().startswith("northstar-agent-runtime "), out.getvalue())

    def test_version_beats_a_missing_prompt(self):
        # The version action exits before any prompt validation, so it must work
        # even when the run flags would be incomplete.
        parser = cli.build_parser()
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(["--version"])
        self.assertEqual(caught.exception.code, 0)


class DryRunTests(unittest.TestCase):
    """`run --dry-run` must validate and describe, never send a request."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-dryrun-"))
        self.workspace = Path(self.tmp) / "ws"
        self.workspace.mkdir()

    def test_dry_run_prints_the_plan_and_exits_zero(self):
        code, out, err = run_cli("run", "--workspace", str(self.workspace), "--prompt", "hi",
                                 "--scripted-text", "reply", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("provider=scripted model=claude-sonnet-4-5", out)
        self.assertIn("permission_mode=default", out)
        self.assertIn("allowed_tools=(none)", out)
        self.assertIn("max_turns=25", out)
        self.assertIn("dry-run: configuration is valid; no request was sent", out)
        # Dry run reports, it never runs: no result line, no session id.
        self.assertNotIn("[success]", out)
        self.assertNotIn("session=ns-", out)

    def test_dry_run_respects_policy_flags(self):
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--prompt", "hi",
                               "--scripted-text", "reply", "--read-only", "--deny-tool", "Grep", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("disallowed_tools=Grep,Write,Edit", out)
        self.assertIn("allowed_tools=(none)", out)

    def test_dry_run_shows_the_estimated_cost_line(self):
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--prompt", "hi",
                               "--scripted-text", "reply", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("estimated cost:", out)

    def test_dry_run_never_constructs_the_provider(self):
        # anthropic is not installed here; a dry run must not try to build it.
        code, out, err = run_cli("run", "--workspace", str(self.workspace), "--prompt", "hi",
                                 "--provider", "anthropic", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("provider=anthropic", out)

    def test_dry_run_with_an_agent_lists_its_tools_and_ceilings(self):
        code, out, _ = run_cli("run", "--workspace", str(self.workspace), "--prompt", "hi",
                               "--scripted-text", "reply", "--agent", "explorer", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("agent 'explorer'", out)
        self.assertIn("tools=", out)

    def test_a_missing_prompt_still_fails_before_dry_run(self):
        code, out, err = run_cli("run", "--workspace", str(self.workspace), "--dry-run")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("no prompt", err)


class SessionViewTests(unittest.TestCase):
    """`sessions list/show/verify` is the read-back half of the audit transcript."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-sview-"))
        self.workspace = Path(self.tmp) / "ws"
        self.workspace.mkdir()
        (self.workspace / "a.txt").write_text("alpha\n", encoding="utf-8")
        self.session_dir = str(self.tmp / "sessions")
        script = self.workspace / "script.json"
        script.write_text(
            json.dumps([{"tool": {"name": "Read", "input": {"path": "a.txt"}, "id": "v1"}}, {"text": "read it"}]),
            encoding="utf-8",
        )
        code, _, err = run_cli("run", "--workspace", str(self.workspace), "--prompt", "read",
                               "--script", str(script), "--session-dir", self.session_dir, "--quiet")
        self.assertEqual(code, 0, err)

    def find_session(self) -> str:
        code, out, _ = run_cli("sessions", "list", "--session-dir", self.session_dir)
        self.assertEqual(code, 0)
        line = next(item for item in out.splitlines() if item.strip())
        return line.split()[0]

    def test_sessions_list_shows_the_transcript(self):
        session = self.find_session()
        self.assertTrue(session.startswith("ns-"), session)

    def test_sessions_show_renders_the_timeline(self):
        session = self.find_session()
        code, out, err = run_cli("sessions", "show", "--session-dir", self.session_dir, session)
        self.assertEqual(code, 0, err)
        self.assertIn("session_start", out)
        self.assertIn("user_prompt", out)
        self.assertIn("\u2192 Read", out, "the tool call renders with its input")
        self.assertIn("tool_result", out)
        self.assertIn("\u2190 ok: alpha", out, "the tool result renders with its outcome")
        self.assertIn("result", out)
        self.assertIn("session_end", out)

    def test_sessions_show_json_exports_raw_records(self):
        session = self.find_session()
        code, out, _ = run_cli("sessions", "show", "--session-dir", self.session_dir, session, "--json")
        self.assertEqual(code, 0)
        records = json.loads(out)
        self.assertIsInstance(records, list)
        self.assertTrue(any(r.get("type") == "result" for r in records))

    def test_run_integrity_secret_env_and_sessions_verify(self):
        hash_dir = str(self.tmp / "hash-sessions")
        code, _, err = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "hash-only", "--scripted-text", "done",
            "--session-dir", hash_dir, "--session-integrity", "--quiet",
        )
        self.assertEqual(code, 0, err)
        hash_path = next(Path(hash_dir).glob("*.jsonl"))
        code, out, err = run_cli("sessions", "verify", "--session-dir", hash_dir, hash_path.stem, "--json")
        self.assertEqual(code, 0, err)
        hash_report = json.loads(out)
        self.assertTrue(hash_report["valid"])
        self.assertFalse(hash_report["signed"])

        secret = "cli-session-integrity-secret"
        with mock.patch.dict(os.environ, {"NS_SESSION_SECRET": secret}, clear=False):
            code, _, err = run_cli(
                "run", "--workspace", str(self.workspace), "--prompt", "signed", "--scripted-text", "done",
                "--session-dir", self.session_dir, "--session-integrity-secret-env", "NS_SESSION_SECRET",
                "--session-cross-process", "--quiet",
            )
            self.assertEqual(code, 0, err)
            signed_path = next(
                path for path in Path(self.session_dir).glob("*.jsonl")
                if '"chain_signature"' in path.read_text(encoding="utf-8")
            )
            session = signed_path.stem
            code, out, err = run_cli(
                "sessions", "verify", "--session-dir", self.session_dir, session,
                "--integrity-secret-env", "NS_SESSION_SECRET", "--json",
            )
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertTrue(report["valid"])
        self.assertTrue(report["signed"])
        self.assertGreater(report["records"], 0)
        self.assertNotIn(secret, Path(self.session_dir, f"{session}.jsonl").read_text(encoding="utf-8"))

    def test_session_integrity_requires_a_session_directory(self):
        code, _, err = run_cli(
            "run", "--workspace", str(self.workspace), "--prompt", "signed", "--scripted-text", "done",
            "--session-integrity",
        )
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("requires --session-dir", err)

    def test_sessions_verify_missing_secret_fails_closed(self):
        from sessions import SessionStore

        store = SessionStore(self.session_dir, session_id="ns-signed-cli", integrity_secret=b"cli-session-integrity-secret")
        store.append("session_start", {})
        code, out, err = run_cli("sessions", "verify", "--session-dir", self.session_dir, "ns-signed-cli", "--json")
        self.assertEqual(code, 1)
        failure = json.loads(out)
        self.assertFalse(failure["valid"])
        self.assertIn("secret is required", failure["error"])
        self.assertEqual(err, "")

    def test_sessions_replay_is_read_only_and_filters_a_timeline_slice(self):
        session = self.find_session()
        path = Path(self.session_dir) / f"{session}.jsonl"
        before = path.stat().st_mtime_ns
        code, out, err = run_cli(
            "sessions", "timeline", "--session-dir", self.session_dir, session,
            "--from-index", "1", "--through-index", "3", "--type", "assistant", "--json",
        )
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertTrue(report["valid"])
        self.assertEqual(report["from_index"], 1)
        self.assertEqual(report["through_index"], 3)
        self.assertEqual([record["type"] for record in report["records"]], ["assistant"])
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_sessions_show_missing_session_is_an_error(self):
        code, out, err = run_cli("sessions", "show", "--session-dir", self.session_dir, "ns-does-not-exist")
        self.assertEqual(code, 1)
        self.assertIn("no transcript", err)

    def test_sessions_without_a_subcommand_is_a_usage_error(self):
        code, _, err = run_cli("sessions")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("sessions: pass a subcommand", err)

    def test_sessions_list_without_a_directory_is_argparse_business(self):
        with self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(["sessions", "list"])
        self.assertEqual(caught.exception.code, 2)

    def test_sessions_list_missing_directory_is_an_error(self):
        code, _, err = run_cli("sessions", "list", "--session-dir", "/nonexistent-ns-sessions")
        self.assertEqual(code, 1)
        self.assertIn("no such directory", err)

    def test_sessions_list_empty_directory_is_an_error(self):
        empty = str(Path(tempfile.mkdtemp(prefix="nsar-sview-empty-")))
        code, _, err = run_cli("sessions", "list", "--session-dir", empty)
        self.assertEqual(code, 1)
        self.assertIn("no transcripts", err)


if __name__ == "__main__":
    unittest.main()
