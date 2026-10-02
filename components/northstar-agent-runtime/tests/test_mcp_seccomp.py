"""MCP server seccomp: the Shell process backend's BPF denylist, reused for MCP.

A compromised or malicious MCP server is third-party code the operator chose
to run; the denylist over escape primitives (ptrace, module loading, BPF,
mount, keyrings, ...) raises its cost without touching file access, so
legitimate stdio servers keep working.
"""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import sys as _sys
_sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_client
from mcp_client import McpError, McpStdioClient
from tools.seccomp import SeccompError, prctl_loader_argv

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_echo_server.py"


class ModeValidationTests(unittest.TestCase):
    def test_bad_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            McpStdioClient("t", ["echo"], seccomp="bogus")

    def test_mode_is_normalized(self):
        client = McpStdioClient("t", ["echo"], seccomp="ON")
        self.assertEqual(client.seccomp, "on")

    def test_seccomp_error_is_a_value_error(self):
        self.assertTrue(issubclass(SeccompError, ValueError))


class SpawnArgvTests(unittest.TestCase):
    def _popen_argv(self, **kwargs):
        """Capture the argv connect() hands to Popen (server never starts)."""
        client = McpStdioClient("t", ["echo", "hi"], timeout_ms=5000, **kwargs)
        with mock.patch.object(
            mcp_client.subprocess, "Popen", side_effect=OSError("boom")
        ) as popen:
            with self.assertRaises(McpError) as caught:
                client.connect()
            self.assertIn("cannot start", str(caught.exception))
        return popen.call_args.args[0]

    def test_off_passes_the_command_through(self):
        self.assertEqual(self._popen_argv(seccomp="off"), ["echo", "hi"])

    def test_auto_wraps_on_linux(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("wrapping needs Linux")
        argv = self._popen_argv(seccomp="auto")
        self.assertEqual(argv[-2:], ["echo", "hi"])
        self.assertEqual(argv[1], "-c")
        self.assertTrue(argv[0].endswith("python3") or "python" in argv[0])

    def test_on_wraps_on_linux(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("wrapping needs Linux")
        argv = self._popen_argv(seccomp="on")
        self.assertEqual(argv[-2:], ["echo", "hi"])

    def test_on_refuses_off_linux(self):
        client = McpStdioClient("t", ["echo"], timeout_ms=5000, seccomp="on")
        with mock.patch.object(mcp_client.sys, "platform", "darwin"):
            with self.assertRaises(McpError) as caught:
                client.connect()
        self.assertIn("requires a platform", str(caught.exception))

    def test_missing_binary_fails_fast_when_wrapped(self):
        # The prctl wrapper's execvp would turn this into a handshake
        # timeout; the client must fail fast with "cannot start" instead.
        if not sys.platform.startswith("linux"):
            self.skipTest("wrapping needs Linux")
        client = McpStdioClient(
            "t", ["definitely-not-a-real-binary-xyz"], timeout_ms=5000, seccomp="auto"
        )
        with self.assertRaises(McpError) as caught:
            client.connect()
        self.assertIn("cannot start", str(caught.exception))

    def test_auto_degrades_off_linux(self):
        with mock.patch.object(mcp_client.sys, "platform", "darwin"):
            self.assertEqual(self._popen_argv(seccomp="auto"), ["echo", "hi"])


class RealKernelTests(unittest.TestCase):
    """On Linux: the filter is really loaded and MCP stdio still works."""

    def _filters(self, seccomp):
        client = McpStdioClient(
            "t",
            ["sh", "-c", "grep '^Seccomp_filters:' /proc/self/status"],
            timeout_ms=5000,
            seccomp=seccomp,
        )
        proc = subprocess.run(
            client._spawn_argv(), capture_output=True, text=True, timeout=30
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return int(proc.stdout.strip().split(":")[1])

    def test_filter_is_really_loaded_through_client_wrapping(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        self.assertEqual(self._filters("auto"), self._filters("off") + 1)

    def test_denied_syscall_gets_eperm_through_client_wrapping(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        import platform

        from tools.seccomp import denied_syscalls

        arch = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(platform.machine())
        if arch is None:
            self.skipTest("no verified table for this arch")
        nr = denied_syscalls(arch)["clock_settime"]
        code = (
            "import ctypes; l=ctypes.CDLL(None, use_errno=True);"
            f"r=l.syscall({nr}, 0, 0); print(ctypes.get_errno())"
        )
        argv = prctl_loader_argv(["python3", "-c", code])
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "1")  # EPERM, not EFAULT

    def test_wrapped_fixture_server_still_handshakes(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        client = McpStdioClient(
            "demo", ["python3", str(FIXTURE)], timeout_ms=8000, seccomp="auto"
        )
        try:
            client.connect()
            self.assertEqual(client.tool_names(), ("echo", "fail"))
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
