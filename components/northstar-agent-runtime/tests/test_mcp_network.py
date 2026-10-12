"""MCP server network confinement: Landlock TCP and UDP denial by default.

The invariant under test: an MCP server spawned with ``network="denied"``
(the default) cannot use TCP or UDP -- the Landlock loader denies both at the
kernel level. ``network="allowed"`` is the explicit opt-in to full host
network. Where the denial cannot be enforced for both (below ABI 10), the
server refuses to start rather than running partially confined.
"""
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import sys as _sys

_sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_client
from mcp_client import McpError, McpStdioClient
from tools.sandbox import landlock_abi_version

LINUX = sys.platform.startswith("linux")
LANDLOCK_IP = LINUX and landlock_abi_version() >= 10


def _workspace():
    d = tempfile.mkdtemp()
    return d


class ModeValidationTests(unittest.TestCase):
    def test_bad_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            McpStdioClient("t", ["echo"], network="bogus")

    def test_mode_is_normalized(self):
        client = McpStdioClient("t", ["echo"], network="DENIED")
        self.assertEqual(client.network, "denied")

    def test_default_is_denied(self):
        client = McpStdioClient("t", ["echo"])
        self.assertEqual(client.network, "denied")


class SpawnArgvTests(unittest.TestCase):
    def test_landlock_bootstrap_uses_runtime_interpreter_not_path(self):
        client = McpStdioClient("t", ["echo", "hi"], network="denied", seccomp="off")
        with mock.patch.object(mcp_client, "landlock_abi_version", return_value=10), \
             mock.patch.object(mcp_client.shutil, "which", return_value="/tmp/untrusted/python3"):
            self.assertEqual(client._apply_network_policy(["echo", "hi"])[0], sys.executable)

    def _popen_argv(self, **kwargs):
        """Capture the argv connect() hands to Popen (server never starts)."""
        client = McpStdioClient("t", ["echo", "hi"], timeout_ms=5000, workspace_root=_workspace(), **kwargs)
        with mock.patch.object(mcp_client.subprocess, "Popen", side_effect=OSError("boom")) as popen:
            with self.assertRaises(McpError):
                client.connect()
        return popen.call_args.args[0]

    def test_allowed_passes_through_without_landlock(self):
        argv = self._popen_argv(network="allowed", seccomp="off")
        self.assertEqual(argv, ["echo", "hi"])

    def test_denied_wraps_with_landlock_on_linux(self):
        with mock.patch.object(mcp_client, "landlock_abi_version", return_value=10):
            argv = self._popen_argv(network="denied", seccomp="off")
        # Landlock loader outside: [python3, -c, LOADER, b64spec, echo, hi]
        self.assertEqual(argv[-2:], ["echo", "hi"])
        self.assertEqual(argv[1], "-c")
        import base64, json

        spec = json.loads(base64.b64decode(argv[3]).decode())
        self.assertFalse(spec["network"], "all handled IP protocols must be denied")
        self.assertTrue(spec["deny_unix_sockets"])
        self.assertEqual(spec["scoped"], ["ABSTRACT_UNIX_SOCKET"])
        self.assertEqual(spec["mode"], "on", "fail-closed, not graceful")

    def test_denied_refuses_without_full_tcp_udp_landlock(self):
        client = McpStdioClient("t", ["echo"], timeout_ms=5000, workspace_root=_workspace(), network="denied")
        for abi in (0, 4, 9):
            with self.subTest(abi=abi), mock.patch.object(mcp_client, "landlock_abi_version", return_value=abi):
                with self.assertRaises(McpError) as caught:
                    client.connect()
            self.assertIn("Landlock ABI 10+", str(caught.exception))


class LiveDenialTests(unittest.TestCase):
    """A real socket connect attempt through the confined spawn path."""

    def _try_connect(self, network: str) -> bool:
        """Spawn `python3 -c <connect>` through the client's spawn path.

        Returns True when the TCP connect succeeded."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        accepted: list[bool] = []

        def _accept():
            try:
                conn, _ = server.accept()
                accepted.append(True)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept, daemon=True)
        thread.start()
        try:
            probe = [
                sys.executable,
                "-c",
                "import socket,sys; s=socket.create_connection(('127.0.0.1', %d), timeout=5); s.close()" % port,
            ]
            client = McpStdioClient(
                "t",
                probe,
                timeout_ms=15000,
                workspace_root=_workspace(),
                network=network,
                seccomp="off",  # isolate the Landlock effect
            )
            argv = client._apply_network_policy(probe)
            proc = subprocess.run(argv, capture_output=True, timeout=30)
            thread.join(timeout=7)
            return proc.returncode == 0 and bool(accepted)
        finally:
            server.close()

    def _try_udp_send(self, network: str) -> bool:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        port = receiver.getsockname()[1]
        try:
            probe = [
                sys.executable,
                "-c",
                "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
                f"s.sendto(b'northstar', ('127.0.0.1', {port}))",
            ]
            client = McpStdioClient(
                "t", probe, timeout_ms=15000, workspace_root=_workspace(),
                network=network, seccomp="off",
            )
            proc = subprocess.run(client._apply_network_policy(probe), capture_output=True, timeout=30)
            try:
                received, _ = receiver.recvfrom(128)
            except TimeoutError:
                received = b""
            return proc.returncode == 0 and received == b"northstar"
        finally:
            receiver.close()

    def _try_unix_connect(self, network: str, *, abstract: bool) -> bool:
        with tempfile.TemporaryDirectory(prefix="northstar-unix-") as directory:
            address = (
                "\0northstar-" + directory.rsplit("-", 1)[-1]
                if abstract
                else f"{directory}/server.sock"
            )
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(address)
            server.listen(1)
            server.settimeout(5)
            probe = [
                sys.executable,
                "-c",
                f"import socket; s=socket.socket(socket.AF_UNIX); s.connect({address!r})",
            ]
            try:
                client = McpStdioClient(
                    "t", probe, timeout_ms=15000, workspace_root=_workspace(),
                    network=network, seccomp="off",
                )
                proc = subprocess.run(client._apply_network_policy(probe), capture_output=True, timeout=30)
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    self.assertNotEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
                    self.assertRegex(
                        proc.stderr.decode(errors="replace"),
                        r"PermissionError|Operation not permitted",
                    )
                    return False
                conn.close()
                return proc.returncode == 0
            finally:
                server.close()

    def test_denied_blocks_tcp_connect(self):
        if not LANDLOCK_IP:
            self.skipTest("needs Linux with Landlock ABI 10+")
        self.assertFalse(self._try_connect("denied"), "a denied server must not complete a TCP connect")

    def test_allowed_permits_tcp_connect(self):
        if not LINUX:
            self.skipTest("spawn path needs Linux")
        self.assertTrue(self._try_connect("allowed"), "an allowed server keeps working")

    def test_denied_blocks_udp_send(self):
        if not LANDLOCK_IP:
            self.skipTest("needs Linux with Landlock ABI 10+")
        self.assertFalse(self._try_udp_send("denied"), "a denied server must not send UDP")

    def test_allowed_permits_udp_send(self):
        if not LINUX:
            self.skipTest("spawn path needs Linux")
        self.assertTrue(self._try_udp_send("allowed"), "an allowed server keeps working")

    def test_denied_blocks_external_abstract_unix_socket(self):
        if not LANDLOCK_IP:
            self.skipTest("needs Linux with Landlock ABI 10+")
        self.assertFalse(self._try_unix_connect("denied", abstract=True))

    def test_denied_blocks_pathname_unix_socket(self):
        if not LANDLOCK_IP:
            self.skipTest("needs Linux with Landlock ABI 10+")
        self.assertFalse(self._try_unix_connect("denied", abstract=False))


if __name__ == "__main__":
    unittest.main()
