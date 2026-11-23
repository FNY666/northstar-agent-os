import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from remote_transport import SSHForwardTimeout, SSHSocketForward, SSHForwardConfig  # noqa: E402


class RemoteTransportTests(unittest.TestCase):
    def test_argv_is_safe_and_uses_the_canonical_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SSHForwardConfig(worker="deploy@worker", local_state_dir=Path(directory))
            argv = config.argv()
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ExitOnForwardFailure=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        self.assertIn("-L", argv)
        forward = argv[argv.index("-L") + 1]
        self.assertTrue(argv[-1].endswith("deploy@worker"))
        self.assertIn("sidecar.sock:/var/run/northstar-codex/sidecar.sock", forward)

    def test_config_rejects_shell_shaped_inputs(self):
        with self.assertRaises(ValueError):
            SSHForwardConfig(worker="deploy@worker;touch /tmp/pwned")
        with self.assertRaises(ValueError):
            SSHForwardConfig(worker="deploy@worker", remote_socket="relative.sock")

    def test_fake_ssh_forward_becomes_ready_and_is_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            script = Path(directory) / "fake_ssh.py"
            script.write_text(
                "import os, socket, sys, time\n"
                "path = os.environ['FAKE_SOCKET']\n"
                "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "server.bind(path); server.listen(1)\n"
                "signal = __import__('signal')\n"
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
                "while True:\n"
                "    conn, _ = server.accept(); conn.close()\n",
                encoding="utf-8",
            )
            config = SSHForwardConfig(worker="fake", local_state_dir=state, ssh_binary=sys.executable)

            def popen(argv, **kwargs):
                env = dict(os.environ, FAKE_SOCKET=str(config.local_socket))
                return __import__("subprocess").Popen(
                    [sys.executable, str(script)], env=env, **kwargs
                )

            forward = SSHSocketForward(config, popen=popen).start()
            try:
                self.assertEqual(forward.wait_ready(), config.local_socket)
                self.assertTrue(forward.is_alive())
                self.assertEqual(config.local_socket.stat().st_mode & 0o777, 0o755)
            finally:
                forward.close()
                forward.close()
            self.assertFalse(config.local_socket.exists())
            self.assertFalse(forward.is_alive())

    def test_ready_timeout_closes_a_live_forward(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SSHForwardConfig(worker="fake", local_state_dir=Path(directory))

            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
            try:
                forward = SSHSocketForward(config, popen=lambda *args, **kwargs: process).start()
                with self.assertRaises(SSHForwardTimeout):
                    forward.wait_ready(timeout_seconds=0.05)
                self.assertIsNone(forward.process)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    unittest.main()
