"""Repository-declared lifecycle hooks: the narrow, fail-closed subset.

The contract this module promises is mostly about what it *refuses*: no shell, no
absolute interpreter paths, no scripts outside the workspace, no events that could
widen behaviour, and no execution at all unless a human passed
``--enable-workspace-hooks``.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase, tool_turn

def _monotonic() -> float:
    import time

    return time.monotonic()


import command_hooks
from command_hooks import (
    ALLOWED_INTERPRETERS,
    CommandHookError,
    build_callback,
    parse_hooks,
    register_into,
    summarise,
)
from hooks import HookInput, HookRegistry
POLICY = "schema_version = \"northstar.policy.v1\"\n"


def _script(root: Path, body: str, *, name: str = "gate.py") -> str:
    path = root / ".northstar" / "hooks" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return f".northstar/hooks/{name}"


class _Completed:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class ParseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-hooks-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)
        self.root.mkdir(exist_ok=True)
        (self.root / ".northstar").mkdir(exist_ok=True)

    def _parse(self, entries, **kwargs):
        return parse_hooks(entries, workspace=self.root, **kwargs)

    def test_a_valid_entry_parses(self):
        script = _script(self.root, "pass\n")
        hooks = self._parse([{"event": "PreToolUse", "script": script}])
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0].event, "PreToolUse")
        self.assertEqual(hooks[0].timeout_ms, command_hooks.DEFAULT_TIMEOUT_MS)
        self.assertIsNone(hooks[0].interpreter)

    def test_there_is_no_command_key(self):
        script = _script(self.root, "pass\n")
        with self.assertRaises(CommandHookError) as caught:
            self._parse([{"event": "PreToolUse", "script": script, "command": "echo hi"}])
        self.assertIn("no 'command' key", str(caught.exception))

    def test_shell_metacharacters_have_noway_to_exist(self):
        # Because there is no command string, the classic injection surface is
        # absent by construction rather than filtered.
        self.assertNotIn("command", command_hooks._ALLOWED_KEYS)
        self.assertNotIn("args", command_hooks._ALLOWED_KEYS)
        self.assertNotIn("shell", command_hooks._ALLOWED_KEYS)
        self.assertNotIn("env", command_hooks._ALLOWED_KEYS)

    def test_only_veto_capable_events_may_be_declared(self):
        script = _script(self.root, "pass\n")
        for event in ("PostToolUse", "Stop", "SessionEnd", "PostToolUseFailure"):
            with self.subTest(event=event):
                with self.assertRaises(CommandHookError) as caught:
                    self._parse([{"event": event, "script": script}])
                self.assertIn("veto-capable", str(caught.exception))

    def test_a_script_outside_the_workspace_is_refused(self):
        outside = Path(support.tempfile.mkdtemp(prefix="nsar-outside-"))
        self.addCleanup(support.shutil.rmtree, outside, True)
        victim = outside / "evil.py"
        victim.write_text("pass\n", encoding="utf-8")
        with self.assertRaises(CommandHookError) as caught:
            self._parse([{"event": "PreToolUse", "script": str(victim)}])
        self.assertIn("workspace-relative", str(caught.exception))
        with self.assertRaises(CommandHookError):
            self._parse([{"event": "PreToolUse", "script": "../evil.py"}])

    def test_a_symlinked_script_is_refused_not_followed(self):
        outside = Path(support.tempfile.mkdtemp(prefix="nsar-out2-"))
        self.addCleanup(support.shutil.rmtree, outside, True)
        victim = outside / "evil.py"
        victim.write_text("pass\n", encoding="utf-8")
        link = self.root / "hook-link.py"
        try:
            link.symlink_to(victim)
        except (OSError, NotImplementedError):  # pragma: no cover - host policy
            self.skipTest("symlinks are unavailable here")
        with self.assertRaises(CommandHookError) as caught:
            self._parse([{"event": "PreToolUse", "script": "hook-link.py"}])
        self.assertIn("outside the workspace", str(caught.exception))

    def test_a_missing_script_is_refused(self):
        with self.assertRaises(CommandHookError) as caught:
            self._parse([{"event": "PreToolUse", "script": ".northstar/hooks/nope.py"}])
        self.assertIn("does not exist", str(caught.exception))

    def test_interpreters_are_an_allowlist_not_a_path(self):
        script = _script(self.root, "pass\n")
        for bad in ("/bin/sh", "../sh", "rm", "python2"):
            with self.subTest(interpreter=bad):
                with self.assertRaises(CommandHookError) as caught:
                    self._parse([{"event": "PreToolUse", "script": script, "interpreter": bad}])
                self.assertIn("must be one of", str(caught.exception))
        for good in ALLOWED_INTERPRETERS:
            hooks = self._parse([{"event": "PreToolUse", "script": script, "interpreter": good}])
            self.assertEqual(hooks[0].interpreter, good)

    def test_timeouts_are_bounded(self):
        script = _script(self.root, "pass\n")
        for bad in (0, 50, 10_001, "fast", True):
            with self.subTest(timeout_ms=bad):
                with self.assertRaises(CommandHookError):
                    self._parse([{"event": "PreToolUse", "script": script, "timeout_ms": bad}])

    def test_tool_matchers_must_name_a_known_tool(self):
        script = _script(self.root, "pass\n")
        with self.assertRaises(CommandHookError):
            self._parse([{"event": "PreToolUse", "script": script, "tool": "RmRF"}], known_tools=("Read", "Write"))
        hooks = self._parse([{"event": "PreToolUse", "script": script, "tool": "Write"}], known_tools=("Read", "Write"))
        self.assertEqual(hooks[0].tool, "Write")

    def test_hook_count_is_capped(self):
        script = _script(self.root, "pass\n")
        with self.assertRaises(CommandHookError):
            self._parse([{"event": "PreToolUse", "script": script}] * (command_hooks.MAX_HOOKS + 1))

    def test_the_display_form_never_leaks_the_absolute_path(self):
        script = _script(self.root, "pass\n")
        hooks = self._parse([{"event": "PreToolUse", "script": script}])
        payload = hooks[0].as_dict()
        self.assertEqual(payload["script"], "gate.py")
        self.assertNotIn(str(self.root), json.dumps(payload))


class VerdictTests(unittest.TestCase):
    """What a hook can say, and what happens when it cannot say it."""

    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-hooks-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)
        self.root.mkdir(exist_ok=True)
        (self.root / ".northstar").mkdir(exist_ok=True)
        self.script = _script(self.root, "pass\n")

    def _callback(self, runner):
        hook = parse_hooks([{"event": "PreToolUse", "script": self.script}], workspace=self.root)[0]
        return build_callback(hook, workspace=self.root, runner=runner)

    def test_registered_hook_refuses_changed_bytes_before_dispatch(self):
        relative = _script(self.root, "SAFE_HOOK_BYTES\n", name="guard.py")
        original = self.root / ".northstar" / "hooks" / "guard.py"
        hook = parse_hooks([{"event": "PreToolUse", "script": relative}], workspace=self.root)[0]
        seen = []
        def runner(argv, **kwargs):
            seen.append(Path(argv[-1]).read_bytes())
            return _Completed()
        callback = build_callback(hook, workspace=self.root, runner=runner)
        original.write_text("UNREVIEWED_HOOK_BYTES\n", encoding="utf-8")
        result = callback(HookInput(event="PreToolUse", tool_name="Write"))
        self.assertEqual(result.decision, "deny")
        self.assertEqual(seen, [], "changed script must never be dispatched")

    def test_direct_exec_hook_keeps_original_path_and_mode(self):
        relative = _script(self.root, "#!/bin/sh\necho safe\n", name="direct.sh")
        original = self.root / ".northstar" / "hooks" / "direct.sh"
        original.chmod(0o755)
        hook = parse_hooks([{"event": "PreToolUse", "script": relative}], workspace=self.root)[0]
        seen = []
        def runner(argv, **kwargs):
            seen.append(Path(argv[-1]) == original)
            return _Completed()
        callback = build_callback(hook, workspace=self.root, runner=runner)
        callback(HookInput(event="PreToolUse"))
        self.assertEqual(seen, [True])
        self.assertEqual(original.stat().st_mode & 0o777, 0o755)

    def test_json_verdict_is_coerced(self):
        callback = self._callback(lambda *a, **k: _Completed(stdout=json.dumps({"decision": "deny", "reason": "no"})))
        result = callback(HookInput(event="PreToolUse", tool_name="Write"))
        self.assertEqual((result.decision, result.reason), ("deny", "no"))

    def test_exit_two_is_a_deny_carrying_stderr(self):
        callback = self._callback(lambda *a, **k: _Completed(stderr="policy says stop\n", returncode=2))
        result = callback(HookInput(event="PreToolUse", tool_name="Write"))
        self.assertEqual(result.decision, "deny")
        self.assertIn("policy says stop", result.reason)

    def test_silence_is_noop(self):
        callback = self._callback(lambda *a, **k: _Completed())
        self.assertEqual(callback(HookInput(event="PreToolUse")).decision, "noop")

    def test_a_non_zero_exit_raises_into_a_fail_closed_veto(self):
        callback = self._callback(lambda *a, **k: _Completed(stderr="crash", returncode=7))
        with self.assertRaises(CommandHookError):
            callback(HookInput(event="PreToolUse"))

    def test_an_unparseable_verdict_raises_instead_of_passing(self):
        callback = self._callback(lambda *a, **k: _Completed(stdout="i allow it"))
        with self.assertRaises(CommandHookError):
            callback(HookInput(event="PreToolUse"))

    def test_the_registry_turns_a_raising_hook_into_a_deny(self):
        # The safety property in one assertion: a broken hook is a veto, never a
        # green light, because HookRegistry.fail-closes on exceptions for vetoes.
        callback = self._callback(lambda *a, **k: (_ for _ in ()).throw(OSError("gone")))
        registry = HookRegistry()
        registry.register("PreToolUse", callback, name="gate")
        outcome = registry.fire("PreToolUse", HookInput(event="PreToolUse", tool_name="Write"))
        self.assertTrue(outcome.denied)
        self.assertIn("fail closed", outcome.deny_reason)

    def test_the_hook_sees_the_event_payload_but_nothing_else(self):
        seen: dict = {}

        def runner(argv, **kwargs):
            seen["payload"] = json.loads(kwargs["input_text"])
            seen["argv"] = argv
            seen["cwd"] = kwargs["cwd"]
            return _Completed()

        callback = self._callback(runner)
        callback(HookInput(event="PreToolUse", tool_name="Write", tool_input={"path": "a.txt"}, session_id="s-1"))
        self.assertEqual(seen["payload"]["tool_name"], "Write")
        self.assertEqual(seen["payload"]["tool_input"], {"path": "a.txt"})
        self.assertEqual(Path(seen["cwd"]).resolve(), self.root.resolve())


class RealSubprocessTests(unittest.TestCase):
    """The production path: a scrubbed environment, capped output, group cleanup."""

    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-hooks-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)
        self.root.mkdir(exist_ok=True)
        (self.root / ".northstar").mkdir(exist_ok=True)

    @unittest.skipUnless(support.shutil.which("python3"), "needs python3 on PATH")
    def test_credentials_never_cross_into_hook_code(self):
        sentinel = "leak-me-not"
        os.environ["ANTHROPIC_API_KEY"] = sentinel
        os.environ["NORTHSTAR_TEST_ONLY"] = sentinel
        self.addCleanup(os.environ.pop, "ANTHROPIC_API_KEY", None)
        os.environ.pop("NORTHSTAR_TEST_ONLY", None)
        # The hook reports the environment it was actually given, so the assertion
        # is about the child, not about how this module builds a dict.
        script = _script(
            self.root,
            "import json,os,sys\nsys.stdin.read()\n"
            "print(json.dumps({'decision':'noop','data':{'env':sorted(os.environ)}}))\n",
            name="env.py",
        )
        hook = parse_hooks(
            [{"event": "PreToolUse", "script": script, "interpreter": "python3"}], workspace=self.root
        )[0]
        result = build_callback(hook, workspace=self.root)(HookInput(event="PreToolUse"))
        self.assertEqual(result.decision, "noop", result.reason)
        visible = result.data["env"]
        self.assertNotIn("ANTHROPIC_API_KEY", visible)
        self.assertNotIn("NORTHSTAR_TEST_ONLY", visible)
        self.assertIn("PATH", visible)

    @unittest.skipUnless(sys.executable, "needs a python interpreter")
    def test_a_hanging_hook_is_killed_and_denies(self):
        script = _script(self.root, "import time\ntime.sleep(5)\n", name="slow.py")
        hook = parse_hooks(
            [{"event": "PreToolUse", "script": script, "interpreter": "python3", "timeout_ms": 300}],
            workspace=self.root,
        )[0]
        started = _monotonic()
        result = build_callback(hook, workspace=self.root)(HookInput(event="PreToolUse"))
        elapsed = _monotonic() - started
        self.assertEqual(result.decision, "deny")
        self.assertIn("timed out", result.reason)
        # The script sleeps 5s against a 0.3s budget: returning promptly is the
        # proof the deadline (and the group kill) fired. If the bound is ever
        # removed this fails in seconds rather than hanging the suite.
        self.assertLess(elapsed, 2, f"the timeout did not bound the hook: {elapsed:.1f}s")

    def test_raw_output_overflow_is_refused_before_a_verdict(self):
        for stream, limit in (("stdout", command_hooks.MAX_STDOUT_BYTES), ("stderr", command_hooks.MAX_STDERR_BYTES)):
            with self.subTest(stream=stream):
                code = f"import sys;sys.{stream}.write('x'*{limit + 1})"
                with self.assertRaisesRegex(CommandHookError, "output.*limit"):
                    command_hooks._run_bounded([sys.executable, "-c", code], cwd=str(self.root), input_text="{}", timeout_s=2)

    def test_output_limits_count_utf8_bytes_not_characters(self):
        code = "import sys;sys.stdout.buffer.write(('测'*22000).encode('utf-8'))"
        with self.assertRaisesRegex(CommandHookError, "output.*limit"):
            command_hooks._run_bounded([sys.executable, "-c", code], cwd=str(self.root), input_text="{}", timeout_s=2)

    def test_stdin_and_output_are_drained_concurrently(self):
        payload = "x" * 200000
        code = (
            "import sys\n"
            "sys.stderr.write('e'*8000);sys.stderr.flush()\n"
            "data=sys.stdin.read()\n"
            "print(len(data))\n"
        )
        completed = command_hooks._run_bounded([sys.executable, "-c", code], cwd=str(self.root), input_text=payload, timeout_s=3)
        self.assertEqual(completed.stdout.strip(), str(len(payload)))
        self.assertEqual(len(completed.stderr), 8000)

    def test_valid_json_followed_by_excess_whitespace_is_not_accepted(self):
        body = "import sys;print('{\"decision\":\"allow\"}');sys.stdout.write(' '*64000)"
        script = _script(self.root, body, name="allow-flood.py")
        hook = parse_hooks([{"event": "PreToolUse", "script": script, "interpreter": "python3"}], workspace=self.root)[0]
        with self.assertRaisesRegex(CommandHookError, "output.*limit"):
            build_callback(hook, workspace=self.root)(HookInput(event="PreToolUse"))

    def test_timeout_keeps_the_original_hook_budget(self):
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            command_hooks._run_bounded([sys.executable, "-c", "import time;time.sleep(10)"], cwd=str(self.root), input_text="{}", timeout_s=.2)
        self.assertEqual(caught.exception.timeout, .2)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "killpg"), "requires process groups")
    def test_term_ignoring_child_is_killed_after_leader_exits(self):
        pidfile = self.root / "grandchild.pid"
        child = "import signal,time,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)"
        leader = (
            "import subprocess,sys,pathlib,time\n"
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[1]],stdout=subprocess.PIPE,text=True)\n"
            "assert p.stdout.readline().strip() == 'ready'\n"
            "pathlib.Path(sys.argv[2]).write_text(str(p.pid))\n"
            "time.sleep(30)\n"
        )
        pid = None
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                command_hooks._run_bounded([sys.executable, "-c", leader, child, str(pidfile)], cwd=str(self.root), input_text="{}", timeout_s=2)
            self.assertTrue(pidfile.exists(), "grandchild must start before timeout")
            pid = int(pidfile.read_text())
            deadline = _monotonic() + 2
            while _monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                # Linux can retain a zombie after kill until init reaps it.
                status = Path(f"/proc/{pid}/stat")
                if status.exists() and status.read_text().split(")", 1)[1].split()[0] == "Z":
                    break
                import time
                time.sleep(.02)
            else:
                self.fail("TERM-ignoring grandchild survived leader exit")
        finally:
            if pid is None and pidfile.exists():
                pid = int(pidfile.read_text())
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(sys.executable, "needs a python interpreter")
    def test_a_script_that_floods_is_capped(self):
        script = _script(self.root, "print('x' * 4_000_000)\n", name="flood.py")
        hook = parse_hooks(
            [{"event": "PreToolUse", "script": script, "interpreter": "python3", "timeout_ms": 4_000}],
            workspace=self.root,
        )[0]
        # Truncated output is not valid JSON, so the run is refused rather than
        # guessed at - the cap cannot be used to smuggle a permissive verdict.
        with self.assertRaises(CommandHookError):
            build_callback(hook, workspace=self.root)(HookInput(event="PreToolUse"))


class CleanupFailureTests(unittest.TestCase):
    def test_selector_setup_failure_does_not_spawn(self):
        with patch.object(command_hooks.selectors, "DefaultSelector", side_effect=OSError("selector setup")), patch.object(command_hooks.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(OSError, "selector setup"):
                command_hooks._run_bounded(["dummy"], cwd="/tmp", input_text="{}", timeout_s=1)
            spawn.assert_not_called()

    def test_spawn_failure_closes_selector(self):
        selector = MagicMock()
        with patch.object(command_hooks.selectors, "DefaultSelector", return_value=selector), patch.object(command_hooks.subprocess, "Popen", side_effect=OSError("spawn failed")):
            with self.assertRaisesRegex(OSError, "spawn failed"):
                command_hooks._run_bounded(["dummy"], cwd="/tmp", input_text="{}", timeout_s=1)
        selector.close.assert_called_once()

    def test_cleanup_failures_cannot_skip_termination_or_mask_primary_error(self):
        selector, process = MagicMock(), MagicMock()
        selector.register.side_effect = ValueError("primary registration failure")
        selector.close.side_effect = OSError("selector close failure")
        process.stdin.closed = process.stdout.closed = process.stderr.closed = False
        process.stdout.close.side_effect = OSError("pipe close failure")
        with patch.object(command_hooks.selectors, "DefaultSelector", return_value=selector), patch.object(command_hooks.subprocess, "Popen", return_value=process), patch.object(command_hooks.os, "set_blocking"), patch.object(command_hooks, "_terminate_group", side_effect=OSError("group cleanup failure")) as terminate:
            with self.assertRaisesRegex(ValueError, "primary registration failure"):
                command_hooks._run_bounded(["dummy"], cwd="/tmp", input_text="{}", timeout_s=1)
        terminate.assert_called_once_with(process)
        process.stdin.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_cleanup_failure_after_success_cannot_return_a_verdict(self):
        selector, process = MagicMock(), MagicMock()
        selector.get_map.return_value = {}
        process.wait.return_value = 0
        process.stdin.closed = process.stdout.closed = process.stderr.closed = False
        with patch.object(command_hooks.selectors, "DefaultSelector", return_value=selector), patch.object(command_hooks.subprocess, "Popen", return_value=process), patch.object(command_hooks.os, "set_blocking"), patch.object(command_hooks, "_terminate_group", side_effect=OSError("group cleanup failure")):
            with self.assertRaisesRegex(CommandHookError, "cleanup failed"):
                command_hooks._run_bounded(["dummy"], cwd="/tmp", input_text="{}", timeout_s=1)


class RegistryAndSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-hooks-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)
        self.root.mkdir(exist_ok=True)
        (self.root / ".northstar").mkdir(exist_ok=True)

    def test_register_into_wires_events_and_matchers(self):
        script = _script(self.root, "pass\n")
        hooks = parse_hooks(
            [{"event": "PreToolUse", "script": script, "tool": "Write"}, {"event": "SessionStart", "script": script}],
            workspace=self.root,
        )
        registry = HookRegistry()
        names = register_into(registry, hooks, workspace=self.root)
        self.assertEqual(len(names), 2)
        counts = registry.counts()
        self.assertEqual((counts["PreToolUse"], counts["SessionStart"]), (1, 1))

    def test_summarise_is_honest_about_being_disabled(self):
        script = _script(self.root, "pass\n")
        hooks = parse_hooks([{"event": "PreToolUse", "script": script}], workspace=self.root)
        self.assertIn("IGNORED", summarise(hooks, enabled=False))
        self.assertIn("PreToolUse", summarise(hooks, enabled=True))
        self.assertEqual(summarise((), enabled=True), "none declared")


class PolicyFileRoundTripTests(RuntimeTestCase):
    def test_the_policy_file_carries_hooks_and_rejects_loose_types(self):
        from policy_file import PolicyFileError, load_policy_file

        root = self.workspace(
            {
                ".northstar/config.toml": POLICY + "[[hooks]]\nevent = \"PreToolUse\"\nscript = \".northstar/hooks/gate.py\"\n",
                ".northstar/hooks/gate.py": "pass\n",
            }
        )
        policy = load_policy_file(root)
        self.assertIsNotNone(policy)
        self.assertEqual(len(policy.hooks), 1)
        self.assertIn("hooks", policy.as_dict())
        bad = self.workspace({".northstar/config.toml": POLICY + "hooks = \"echo hi\"\n"})
        with self.assertRaises(PolicyFileError):
            load_policy_file(bad)


class CliGateTests(RuntimeTestCase):
    """``--enable-workspace-hooks`` is the trust decision, and it is loud either way."""

    def _invoke(self, argv):
        import contextlib
        import io

        from cli import main

        out, err = io.StringIO(), io.StringIO()
        saved, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def _workspace(self):
        return self.workspace(
            {
                ".northstar/config.toml": POLICY
                + "[[hooks]]\nevent = \"PreToolUse\"\nscript = \".northstar/hooks/gate.py\"\ninterpreter = \"python3\"\n",
                ".northstar/hooks/gate.py": (
                    "import json,sys\n"
                    "p=json.load(sys.stdin)\n"
                    "if p.get('tool_input',{}).get('path','')=='secret.txt':\n"
                    "    print(json.dumps({'decision':'deny','reason':'out of bounds'}))\n"
                ),
                "notes.txt": "ok\n",
            }
        )

    def _script_file(self, root: Path) -> Path:
        path = root / "script.json"
        path.write_text(
            json.dumps({"turns": [{"tool": {"name": "Write", "input": {"path": "secret.txt", "content": "x"}, "id": "h1"}}, {"text": "done"}]}),
            encoding="utf-8",
        )
        return path

    def test_hooks_are_ignored_by_default(self):
        root = self._workspace()
        script = self._script_file(root)
        code, out, err = self._invoke(
            ["run", "--workspace", str(root), "--prompt", "go", "--provider", "scripted",
             "--script", str(script), "--permission-mode", "acceptEdits"]
        )
        self.assertEqual(code, 0)
        note = err + out
        self.assertIn("IGNORED", note)
        self.assertIn("--enable-workspace-hooks", note, "the note must name the remedy")
        self.assertTrue((root / "secret.txt").exists(), "with hooks off the write goes through unchanged")

    def test_enabled_hooks_veto_a_tool_call(self):
        root = self._workspace()
        script_path = self._script_file(root)
        code, out, err = self._invoke(
            ["run", "--workspace", str(root), "--prompt", "go", "--provider", "scripted",
             "--script", str(script_path), "--permission-mode", "acceptEdits", "--enable-workspace-hooks"]
        )
        self.assertEqual(code, 0)
        self.assertIn("out of bounds", out + err)
        self.assertFalse((root / "secret.txt").exists())

    def test_a_broken_hook_declaration_is_a_usage_error(self):
        root = self.workspace(
            {
                ".northstar/config.toml": POLICY
                + "[[hooks]]\nevent = \"PreToolUse\"\nscript = \".northstar/hooks/gate.py\"\ninterpreter = \"/bin/sh\"\n",
                ".northstar/hooks/gate.py": "pass\n",
            }
        )
        code, out, err = self._invoke(
            ["run", "--workspace", str(root), "--prompt", "go", "--provider", "scripted",
             "--script", str(root / "absent.json"), "--enable-workspace-hooks"]
        )
        self.assertEqual(code, 64)
        self.assertIn("interpreter", err)

    def test_dry_run_reports_the_hook_state(self):
        root = self._workspace()
        code, out, err = self._invoke(["run", "--workspace", str(root), "--prompt", "go", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("IGNORED", out)
        code, out, err = self._invoke(
            ["run", "--workspace", str(root), "--prompt", "go", "--dry-run", "--enable-workspace-hooks"]
        )
        self.assertIn("PreToolUse", out)

    def test_doctor_warns_about_declared_hooks(self):
        root = self._workspace()
        code, out, err = self._invoke(["doctor", "--workspace", str(root)])
        self.assertIn("hooks", out)
        self.assertIn("--enable-workspace-hooks", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
