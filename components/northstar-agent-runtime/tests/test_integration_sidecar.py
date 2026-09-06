"""End-to-end against a *real* sidecar: real ``serve()``, real Unix socket, real
``run_one``, real (fake) codex binary.

This is the only place the two components meet, so it is deliberately not a mock:
the runtime speaks its side of the contract and the sidecar code from
``components/northstar-codex-sidecar`` answers on the other end. Nothing in here
touches a network listener or a model provider's credentials.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import support  # noqa: F401
from support import text_turn, tool_turn

from loop import AgentRuntime, RuntimeConfig
from providers.base import ToolResultBlock
from providers.scripted import ScriptedProvider
from sidecar_client import SIDECAR_MAX_PROMPT_CHARS, SidecarClient

# Stands in for the codex CLI: echoes how many characters it received, records its
# argv and environment, and can be told to fail or to stall.
FAKE_CODEX = """#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path

# The sidecar starts this process with a deliberately tiny environment
# (HOME, CODEX_HOME, PATH), so the test switches are files under CODEX_HOME.
root = Path(os.environ.get("CODEX_HOME", "."))
data = sys.stdin.buffer.read().decode("utf-8", "replace")
audit = {"argv": sys.argv[1:], "chars": len(data), "head": data[:20], "env_keys": sorted(os.environ)}
with open(root / "audit" / "calls.jsonl", "a", encoding="utf-8") as handle:
    handle.write(json.dumps(audit, ensure_ascii=False) + "\\n")
if (root / "DELAY").exists():
    time.sleep(float((root / "DELAY").read_text() or "5"))
if (root / "FAIL").exists():
    sys.stderr.write("codex exploded api_key=sk-should-not-leak\\n")
    raise SystemExit(3)
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "ECHO %d %s" % (len(data), data[:20])}}))
"""


class SidecarIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="nsar-e2e-"))
        cls.workspace = cls.tmp / "workspace"
        cls.workspace.mkdir()
        cls.audit = cls.tmp / "audit"
        cls.audit.mkdir()
        cls.audit_file = cls.audit / "calls.jsonl"
        fake = cls.tmp / "codex"
        fake.write_text(FAKE_CODEX, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        cls.sidecar = support.load_sidecar("sidecar")
        cls.service = support.load_sidecar("service")
        cls.sidecar_socket = support.load_sidecar("sidecar_socket")

        cls.originals = (
            cls.sidecar.CODEX_BIN,
            cls.sidecar.CODEX_HOME,
            cls.sidecar.CODEX_WORKSPACE,
            cls.service.SOCKET_ROOT,
        )
        cls.sidecar.CODEX_BIN = str(fake)
        cls.sidecar.CODEX_HOME = str(cls.tmp)
        cls.sidecar.CODEX_WORKSPACE = str(cls.workspace)
        cls.service.SOCKET_ROOT = cls.tmp

        cls.socket_path = cls.tmp / "sidecar.sock"
        cls.server_errors: list[BaseException] = []
        cls.thread = threading.Thread(target=cls._serve, name="sidecar-under-test", daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 15
        while not cls.socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not cls.socket_path.exists():
            raise AssertionError(f"the sidecar never bound {cls.socket_path}: {cls.server_errors!r}")

    @classmethod
    def _serve(cls) -> None:
        try:
            cls.sidecar_socket.serve(str(cls.socket_path))
        except BaseException as error:  # noqa: BLE001 - surfaced in a failure message
            cls.server_errors.append(error)

    @classmethod
    def tearDownClass(cls) -> None:
        (bin_path, home, workspace_dir, socket_root) = cls.originals
        cls.sidecar.CODEX_BIN = bin_path
        cls.sidecar.CODEX_HOME = home
        cls.sidecar.CODEX_WORKSPACE = workspace_dir
        cls.service.SOCKET_ROOT = socket_root
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers -----------------------------------------------------------
    def calls(self) -> list[dict]:
        if not self.audit_file.exists():
            return []
        return [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def runtime(self, turns, **config_kwargs) -> AgentRuntime:
        config = RuntimeConfig(
            workspace=str(self.workspace),
            sidecar_socket=str(self.socket_path),
            model="claude-sonnet-4-5",
            **config_kwargs,
        )
        return AgentRuntime(provider=ScriptedProvider(turns, model="claude-sonnet-4-5"), config=config)

    def drive(self, runtime: AgentRuntime, prompt: str = "go") -> object:
        report = runtime.run_collect(prompt)
        self.assertEqual(self.server_errors, [], "the sidecar thread died")
        return report

    def tool_payload(self, report) -> dict:
        block = report.transcript[2].tool_results[0]
        self.assertIsInstance(block, ToolResultBlock)
        return json.loads(block.text())

    # -- the socket itself -------------------------------------------------
    def test_the_sidecar_listens_on_a_private_unix_socket(self):
        self.assertTrue(self.socket_path.exists())
        self.assertEqual(os.stat(self.socket_path).st_mode & 0o777, 0o660, "never world-readable")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(10)
            probe.connect(str(self.socket_path))
            probe.sendall(b"\n")
            probe.shutdown(socket.SHUT_WR)
            collected = b""
            while b"\n" not in collected:
                chunk = probe.recv(65536)
                if not chunk:
                    break
                collected += chunk
        reply = json.loads(collected.decode("utf-8"))
        self.assertEqual(reply["status"], "rejected")
        self.assertEqual(reply["errors"], ["invalid JSON request"])

    def test_a_raw_client_round_trip_echoes_through_codex(self):
        client = SidecarClient(str(self.socket_path), timeout_ms=20_000)
        result = client.execute("summarise the change")
        self.assertTrue(result.ok, result.report)
        self.assertTrue(result.text.startswith(f"ECHO {len('summarise the change')} "), result.text)
        self.assertEqual(result.raw["status"], "ok")
        self.assertLess(result.latency_ms, 20_000)

    def test_the_sidecar_only_ever_runs_codex_read_only_and_ephemeral(self):
        SidecarClient(str(self.socket_path), timeout_ms=20_000).execute("check the tree")
        calls = self.calls()
        self.assertGreaterEqual(len(calls), 1)
        argv = calls[-1]["argv"]
        for flag in ("exec", "--json", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check"):
            self.assertIn(flag, argv)
        self.assertNotIn("danger-full-access", argv)

    def test_the_sidecar_environment_holds_no_model_credentials(self):
        SidecarClient(str(self.socket_path), timeout_ms=20_000).execute("check the tree")
        env_keys = self.calls()[-1]["env_keys"]
        self.assertNotIn("ANTHROPIC_API_KEY", env_keys)
        self.assertNotIn("OPENAI_API_KEY", env_keys)
        self.assertTrue({"HOME", "CODEX_HOME", "PATH"} <= set(env_keys))

    # -- the runtime's tool surface ----------------------------------------
    def test_the_delegated_tool_exists_only_because_a_socket_was_configured(self):
        with_socket = self.runtime([text_turn("done")])
        self.assertIn("CodexReadOnly", with_socket.tools.names())
        without = AgentRuntime(
            provider=ScriptedProvider([text_turn("done")], model="claude-sonnet-4-5"),
            config=RuntimeConfig(workspace=str(self.workspace), model="claude-sonnet-4-5"),
        )
        self.assertNotIn("CodexReadOnly", without.tools.names())
        self.assertIn("CodexReadOnly", [tool["name"] for tool in with_socket.tools.to_api()])
        self.assertEqual(without.sidecar, None)

    def test_a_full_run_delegates_to_codex_and_reports_the_answer(self):
        report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": "list the risky lines"}), text_turn("Codex flagged nothing")]))
        self.assertEqual(report.subtype, "success")
        payload = self.tool_payload(report)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("ECHO", payload["text"])
        self.assertEqual(report.tool_calls[0].name, "CodexReadOnly")
        self.assertFalse(report.tool_calls[0].is_error)
        self.assertEqual(report.result.errors, ())
        self.assertEqual(report.final_text, "Codex flagged nothing")

    def test_a_delegated_read_only_call_is_allowed_even_in_plan_mode(self):
        report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": "look"}), text_turn("planning only")], permission_mode="plan"))
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.denials, (), "the sidecar tool cannot mutate anything")
        self.assertEqual(self.tool_payload(report)["status"], "ok")

    def test_a_write_in_the_same_plan_run_is_still_refused(self):
        report = self.drive(
            self.runtime(
                [
                    {"tools": [{"name": "CodexReadOnly", "input": {"prompt": "look"}}, {"name": "Write", "input": {"path": "x.txt", "content": "nope"}}]},
                    text_turn("planning only"),
                ],
                permission_mode="plan",
            )
        )
        self.assertTrue(report.transcript[2].tool_results[1].is_error)
        self.assertFalse((self.workspace / "x.txt").exists())
        self.assertEqual(self.tool_payload(report)["status"], "ok", "the read-only call was unaffected by its neighbour")

    def test_the_prompt_body_never_reaches_a_span(self):
        runtime = self.runtime([tool_turn("CodexReadOnly", {"prompt": "READ-ONLY-SECRET-PROMPT"}), text_turn("done")])
        report = self.drive(runtime)
        dump = json.dumps([record.attributes for record in runtime.tracer.records()], ensure_ascii=False)
        self.assertNotIn("READ-ONLY-SECRET-PROMPT", dump)
        self.assertNotIn("ECHO", dump)
        self.assertIn("tool:CodexReadOnly", [record.name for record in runtime.tracer.records()])
        self.assertFalse(report.result.is_error)

    def test_a_sidecar_failure_is_reported_as_a_tool_error_not_a_crash(self):
        marker = self.tmp / "FAIL"
        marker.write_text("1")
        try:
            report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": "boom"}), text_turn("handled")]))
        finally:
            marker.unlink(missing_ok=True)
        self.assertEqual(report.subtype, "success", "the model sees the failure and carries on")
        block = report.transcript[2].tool_results[0]
        self.assertTrue(block.is_error)
        payload = json.loads(block.text())
        self.assertEqual(payload["status"], "codex_error")
        self.assertNotIn("sk-should-not-leak", block.text(), "the sidecar redacts credentials from stderr")
        self.assertIn("api_key=[REDACTED]", payload["error"])

    def test_a_sidecar_timeout_is_bounded_and_reported(self):
        marker = self.tmp / "DELAY"
        marker.write_text("6")
        try:
            started = time.monotonic()
            report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": "be slow", "timeout_ms": 1000}), text_turn("gave up in time")]))
            elapsed = time.monotonic() - started
        finally:
            marker.unlink(missing_ok=True)
        payload = self.tool_payload(report)
        self.assertEqual(payload["status"], "timeout")
        self.assertTrue(payload["report"].startswith("sidecar status=timeout"))
        self.assertLess(elapsed, 25, f"the deadline must bound the wait, took {elapsed:.1f}s")
        self.assertEqual(report.subtype, "success")

    def test_a_silent_peer_cannot_hang_the_run_forever(self):
        # The socket deadline is the request timeout plus a fixed grace, so a peer
        # that accepts and never answers cannot hold the loop open indefinitely.
        null_path = self.tmp / "silent" / "sidecar.sock"
        null_path.parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(null_path))
        listener.listen(8)
        accepted: list[socket.socket] = []
        peer_ready = threading.Event()

        def accept_and_hold() -> None:
            try:
                connection, _ = listener.accept()
                accepted.append(connection)
                peer_ready.set()
                while peer_ready.is_set():
                    time.sleep(0.05)
            except OSError:
                peer_ready.set()

        peer = threading.Thread(target=accept_and_hold, daemon=True)
        peer.start()
        silent = SidecarClient(str(null_path), timeout_ms=1000, read_grace_s=0.5)
        started = time.monotonic()
        try:
            result = silent.execute("go")
        finally:
            peer_ready.clear()
            listener.close()
            for connection in accepted:
                connection.close()
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(result.status, "transport_unavailable")
        self.assertTrue(result.may_fall_back)
        self.assertTrue(SidecarClient(str(self.socket_path), timeout_ms=10_000).execute("still alive").ok)

    # -- the 100k CJK case --------------------------------------------------
    def test_a_full_size_chinese_prompt_reaches_codex_untouched(self):
        prompt = "测" * SIDECAR_MAX_PROMPT_CHARS
        self.assertEqual(len(prompt), 100_000)
        result = SidecarClient(str(self.socket_path), timeout_ms=30_000).execute(prompt)
        self.assertTrue(result.ok, result.report)
        self.assertEqual(result.text.split(" ")[1], "100000")
        self.assertTrue(result.text.endswith("测" * 20), result.text[:60])
        call = self.calls()[-1]
        self.assertEqual(call["chars"], 100_000, "no characters were lost in transport")
        self.assertEqual(call["head"], "测" * 20)

    def test_a_full_size_chinese_prompt_survives_the_agent_loop(self):
        prompt = "中文" * 50_000
        self.assertEqual(len(prompt), SIDECAR_MAX_PROMPT_CHARS)
        report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": prompt}), text_turn("done")]))
        payload = self.tool_payload(report)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["text"].split(" ")[1], "100000")
        self.assertEqual(self.calls()[-1]["chars"], 100_000)

    def test_one_char_over_the_limit_is_refused_locally_and_never_reaches_codex(self):
        prompt = "中" * (SIDECAR_MAX_PROMPT_CHARS + 1)
        before = len(self.calls())
        result = SidecarClient(str(self.socket_path)).execute(prompt)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.errors, ("prompt exceeds maximum size",))
        self.assertEqual(len(self.calls()), before, "the sidecar was not asked to run anything")

    def test_a_turn_over_the_limit_via_the_tool_is_reported_not_raised(self):
        prompt = "中" * (SIDECAR_MAX_PROMPT_CHARS + 1)
        report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": prompt}), text_turn("sorry")]))
        block = report.transcript[2].tool_results[0]
        self.assertTrue(block.is_error)
        self.assertIn("prompt exceeds maximum size", block.text())
        self.assertEqual(report.subtype, "success")

    # -- concurrency --------------------------------------------------------
    def test_two_parallel_delegations_are_both_served(self):
        before = len(self.calls())
        turn = {
            "tools": [
                {"name": "CodexReadOnly", "input": {"prompt": "first " + "a" * 500}},
                {"name": "CodexReadOnly", "input": {"prompt": "second " + "b" * 500}},
            ]
        }
        report = self.drive(self.runtime([turn, text_turn("both answered")]))
        blocks = report.transcript[2].tool_results
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertFalse(block.is_error)
            self.assertEqual(json.loads(block.text())["status"], "ok")
        calls = self.calls()[before:]
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted(call["chars"] for call in calls), [506, 507], "each connection got its own request")

    def test_the_runtime_never_spawns_codex_itself(self):
        # Delegation is the whole design: the runtime opens a socket, the sidecar
        # forks. A regression here would put a model CLI back under the runtime.
        launched: list[tuple] = []
        original = subprocess.Popen

        class WatchingPopen(original):
            def __init__(self, *args, **kwargs):
                launched.append(args)
                super().__init__(*args, **kwargs)

        try:
            self.sidecar.subprocess.Popen = WatchingPopen
            report = self.drive(self.runtime([tool_turn("CodexReadOnly", {"prompt": "count me"}), text_turn("done")]))
        finally:
            self.sidecar.subprocess.Popen = original
        self.assertEqual(report.subtype, "success")
        self.assertEqual(len(launched), 1, "exactly one process spawn, made inside the sidecar")
        self.assertIn("read-only", launched[0][0])


if __name__ == "__main__":
    unittest.main()
