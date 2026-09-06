"""Integration tests against a REAL northstar-codex-sidecar process.

These start the sidecar's own ``serve()`` in a thread (with
``service.SOCKET_ROOT`` patched to a temp directory), give it a fake
``codex`` executable, and drive it through the runtime's ``CodexReadOnly``
tool over a real Unix socket. No network, no API key.
"""
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path, PurePosixPath

from helpers import make_runtime, tool_results_of
from loop import AgentRuntime, RunConfig
from providers.scripted import ScriptedProvider
from sidecar_client import SidecarClient

COMPONENTS_DIR = Path(__file__).resolve().parents[2]
SIDECAR_DIR = COMPONENTS_DIR / "northstar-codex-sidecar"
RUNTIME_DIR = Path(__file__).resolve().parents[1]

FAKE_CODEX_ECHO = """#!/bin/sh
# Reads the prompt from stdin, reports how many bytes it actually received.
bytes=$(wc -c | tr -d '[:space:]')
printf '%s\\n' "{\\"type\\":\\"item.completed\\",\\"item\\":{\\"type\\":\\"agent_message\\",\\"text\\":\\"ECHO bytes=$bytes\\"}}"
"""

FAKE_CODEX_SLOW = """#!/bin/sh
sleep 30
printf '%s\\n' "{\\"type\\":\\"item.completed\\",\\"item\\":{\\"type\\":\\"agent_message\\",\\"text\\":\\"LATE\\"}}"
"""


def write_fake_codex(directory: Path, script: str) -> Path:
    fake = directory / "fake-codex"
    fake.write_text(script, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return fake


class SidecarServedMixin:
    """Starts a real sidecar serve() with a fake codex in a temp directory."""

    def start_sidecar(self, codex_script: str):
        if str(SIDECAR_DIR) not in sys.path:
            sys.path.insert(0, str(SIDECAR_DIR))
        import service
        import sidecar
        import sidecar_socket

        self.addCleanupsetattr = None  # placeholder to avoid lint confusion
        self._service = service
        self._sidecar = sidecar
        self._sidecar_socket = sidecar_socket

        self._tmp = Path(tempfile.mkdtemp(prefix="nsrt-sidecar-"))
        self._socket_path = self._tmp / "sidecar.sock"

        self._old_socket_root = service.SOCKET_ROOT
        self._old_codex_bin = sidecar.CODEX_BIN
        self._old_codex_home = sidecar.CODEX_HOME
        self._old_codex_workspace = sidecar.CODEX_WORKSPACE

        # Point the service contract at the temp dir so serve() accepts the path.
        service.SOCKET_ROOT = PurePosixPath(self._tmp)
        self._codex_home = self._tmp / "codex-home"
        self._codex_home.mkdir()
        self._codex_workspace = self._tmp / "codex-workspace"
        self._codex_workspace.mkdir()
        fake = write_fake_codex(self._tmp, codex_script)
        sidecar.CODEX_BIN = str(fake)
        sidecar.CODEX_HOME = str(self._codex_home)
        sidecar.CODEX_WORKSPACE = str(self._codex_workspace)

        thread = threading.Thread(target=sidecar_socket.serve, args=(str(self._socket_path),), daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not self._socket_path.exists() and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(self._socket_path.exists(), "sidecar socket never appeared")
        return str(self._socket_path)

    def stop_sidecar(self):
        for module, name, value in (
            (self._service, "SOCKET_ROOT", self._old_socket_root),
            (self._sidecar, "CODEX_BIN", self._old_codex_bin),
            (self._sidecar, "CODEX_HOME", self._old_codex_home),
            (self._sidecar, "CODEX_WORKSPACE", self._old_codex_workspace),
        ):
            setattr(module, name, value)
        if str(SIDECAR_DIR) in sys.path:
            sys.path.remove(str(SIDECAR_DIR))


class SidecarClientDirectTests(unittest.TestCase, SidecarServedMixin):
    def test_client_round_trip_against_real_serve(self):
        self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        client = SidecarClient(self._socket_path)
        result = client.execute("hello sidecar", timeout_ms=10_000)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["text"], f"ECHO bytes={len('hello sidecar'.encode('utf-8'))}")

    def test_client_timeout_status_when_codex_is_slow(self):
        self.start_sidecar(FAKE_CODEX_SLOW)
        self.addCleanup(self.stop_sidecar)
        client = SidecarClient(self._socket_path, timeout=30)
        result = client.execute("slow prompt", timeout_ms=1_000)
        self.assertEqual(result["status"], "timeout")

    def test_transport_unavailable_when_no_listener(self):
        client = SidecarClient(str(Path(tempfile.gettempdir()) / "nsrt-no-such-socket.sock"))
        result = client.execute("hi", timeout_ms=1_000)
        self.assertEqual(result["status"], "transport_unavailable")


class CodexReadOnlyToolTests(unittest.TestCase, SidecarServedMixin):
    def _run_codex_tool(self, socket_path, prompt, timeout_ms=10_000):
        script = [
            {"text": "delegating to codex", "tools": [
                {"name": "CodexReadOnly", "input": {"prompt": prompt, "timeout_ms": timeout_ms}}
            ]},
            "finished",
        ]
        workspace = Path(tempfile.mkdtemp(prefix="nsrt-codex-ws-"))
        runtime = AgentRuntime(
            ScriptedProvider(script),
            RunConfig(workspace=workspace, sidecar_socket=socket_path, permission_mode="bypassPermissions"),
        )
        return runtime, runtime.run("go")

    def test_tool_registered_only_with_socket(self):
        workspace = Path(tempfile.mkdtemp())
        runtime_no = AgentRuntime(ScriptedProvider(["done"]), RunConfig(workspace=workspace))
        self.assertNotIn("CodexReadOnly", runtime_no._tool_registry.names())
        runtime_yes = AgentRuntime(
            ScriptedProvider(["done"]), RunConfig(workspace=workspace, sidecar_socket="/nonexistent/sidecar.sock")
        )
        self.assertIn("CodexReadOnly", runtime_yes._tool_registry.names())

    def test_round_trip_over_real_unix_socket(self):
        socket_path = self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        runtime, report = self._run_codex_tool(socket_path, "Say OK")
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(runtime.provider.calls[1])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["is_error"])
        self.assertEqual(results[0]["content"], "ECHO bytes=6")

    def test_100k_chinese_character_prompt_survives_the_socket(self):
        # The sidecar's documented maximum prompt size, all CJK: 100,000 chars
        # is 300,000 bytes of UTF-8 on the wire.
        socket_path = self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        prompt = "\u4e2d" * 100_000
        runtime, report = self._run_codex_tool(socket_path, prompt, timeout_ms=300_000)
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(runtime.provider.calls[1])
        self.assertFalse(results[0]["is_error"], results[0]["content"])
        self.assertEqual(results[0]["content"], "ECHO bytes=300000")

    def test_oversized_prompt_rejected_before_hitting_the_wire(self):
        socket_path = self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        runtime, report = self._run_codex_tool(socket_path, "x" * 100_001)
        results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("exceeds the sidecar limit", results[0]["content"])

    def test_timeout_out_of_range_rejected(self):
        socket_path = self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        script = [
            {"text": "t", "tools": [{"name": "CodexReadOnly", "input": {"prompt": "hi", "timeout_ms": 500}}]},
            "done",
        ]
        workspace = Path(tempfile.mkdtemp())
        runtime = AgentRuntime(
            ScriptedProvider(script),
            RunConfig(workspace=workspace, sidecar_socket=socket_path, permission_mode="bypassPermissions"),
        )
        runtime.run("go")
        results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("timeout_ms", results[0]["content"])

    def test_codex_timeout_status_surfaces_as_tool_error(self):
        socket_path = self.start_sidecar(FAKE_CODEX_SLOW)
        self.addCleanup(self.stop_sidecar)
        runtime, report = self._run_codex_tool(socket_path, "slow", timeout_ms=1_000)
        results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("timeout", results[0]["content"])
        # the run itself completes: a tool failure is not a run failure
        self.assertEqual(report.result.subtype, "success")

    def test_sidecar_rejects_unknown_fields_through_the_real_protocol(self):
        # Direct client sanity: the sidecar's own validator is the one
        # answering, and its rejection status comes back verbatim.
        socket_path = self.start_sidecar(FAKE_CODEX_ECHO)
        self.addCleanup(self.stop_sidecar)
        import socket as socket_module

        bad_request = {"request_id": "r", "prompt": "OK", "timeout_ms": 1000, "shell": "id"}
        wire = json.dumps(bad_request, ensure_ascii=False).encode() + b"\n"
        with socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(socket_path)
            sock.sendall(wire)
            buffer = b""
            while b"\n" not in buffer:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
        response = json.loads(buffer.decode())
        self.assertEqual(response["status"], "rejected")
        self.assertTrue(any("unknown" in e for e in response["errors"]))


if __name__ == "__main__":
    unittest.main()
