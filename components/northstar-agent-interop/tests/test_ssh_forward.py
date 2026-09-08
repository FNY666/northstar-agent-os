"""Local-only lifecycle tests for the Profile A SSH forward helper."""
from __future__ import annotations

import socket
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from ssh_forward import (  # noqa: E402
    SSHForward,
    SSHForwardConfig,
    SSHForwardError,
    build_ssh_command,
)


_FAKE_SSH = textwrap.dedent(
    r"""
    #!/usr/bin/env python3
    import signal
    import socket
    import sys
    import threading
    import time
    from pathlib import Path

    mode = sys.argv[0]
    if "exit" in Path(mode).name:
        print("fake ssh refused the channel", file=sys.stderr, flush=True)
        raise SystemExit(23)
    if "late" in Path(mode).name:
        time.sleep(2)
        raise SystemExit(24)
    spec = sys.argv[sys.argv.index("-L") + 1]
    local, remote = spec.split(":", 1)
    path = Path(local)
    path.parent.mkdir(parents=True, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(8)

    def bridge(connection):
        upstream = None
        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(remote)
            payload = connection.recv(4096)
            if payload:
                upstream.sendall(payload)
                response = upstream.recv(4096)
                if response:
                    connection.sendall(response)
        except OSError:
            pass
        finally:
            connection.close()
            if upstream is not None:
                upstream.close()

    def stop(signum, frame):
        del signum, frame
        listener.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=bridge, args=(connection,), daemon=True).start()
    """
).lstrip()


def _write_fake_ssh(directory: Path, name: str) -> Path:
    path = directory / name
    path.write_text(_FAKE_SSH, encoding="utf-8")
    path.chmod(0o700)
    return path


class SSHForwardConfigTests(unittest.TestCase):
    def test_command_is_noninteractive_strict_and_not_a_shell_string(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = SSHForwardConfig(
                destination="worker@example.test",
                remote_socket="/var/run/northstar-codex/sidecar.sock",
                local_socket=root / "sidecar.sock",
                known_hosts=root / "known_hosts",
                identity_file=root / "id_ed25519",
            )
            command = build_ssh_command(config)
        self.assertEqual(command[1:3], ("-N", "-T"))
        self.assertIn("ExitOnForwardFailure=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ForwardAgent=no", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertIn("-L", command)
        self.assertNotIn("-c", command)
        self.assertEqual(command[-1], "worker@example.test")

    def test_paths_destination_and_timing_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                {"destination": "-oProxyCommand=bad"},
                {"remote_socket": "relative.sock"},
                {"local_socket": root / "wrong-name.sock"},
                {"server_alive_count_max": 0},
                {"startup_timeout_s": 0},
            )
            base = {
                "destination": "worker@example.test",
                "remote_socket": "/var/run/northstar-codex/sidecar.sock",
                "local_socket": root / "sidecar.sock",
            }
            for override in cases:
                with self.subTest(override=override):
                    with self.assertRaises(ValueError):
                        SSHForwardConfig(**{**base, **override})


class SSHForwardLifecycleTests(unittest.TestCase):
    def _config(self, root: Path, ssh_binary: Path, **overrides: object) -> SSHForwardConfig:
        values: dict[str, object] = {
            "destination": "worker@example.test",
            "remote_socket": "/var/run/northstar-codex/sidecar.sock",
            "local_socket": root / "sidecar.sock",
            "ssh_binary": str(ssh_binary),
            "startup_timeout_s": 2.0,
            "stop_grace_s": 1.0,
        }
        values.update(overrides)
        return SSHForwardConfig(**values)  # type: ignore[arg-type]

    def test_local_fake_forward_waits_for_socket_bridges_a_loopback_pair_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote_root = root / "remote"
            remote_root.mkdir()
            remote_socket = remote_root / "sidecar.sock"
            remote_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            remote_listener.bind(str(remote_socket))
            remote_listener.listen(8)
            stop_remote = threading.Event()

            def serve_remote():
                remote_listener.settimeout(0.1)
                while not stop_remote.is_set():
                    try:
                        connection, _ = remote_listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    with connection:
                        payload = connection.recv(4096)
                        if payload:
                            connection.sendall(payload.upper())

            remote_thread = threading.Thread(target=serve_remote, daemon=True)
            remote_thread.start()
            fake = _write_fake_ssh(root, "fake-ssh.py")
            config = self._config(root, fake, remote_socket=remote_socket)
            try:
                with SSHForward(config) as forward:
                    self.assertTrue(forward.ready)
                    self.assertIsNotNone(forward.pid)
                    self.assertTrue(config.local_socket.exists())
                    forward.check()
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(str(config.local_socket))
                        client.sendall(b"loopback")
                        self.assertEqual(client.recv(4096), b"LOOPBACK")
            finally:
                stop_remote.set()
                remote_listener.close()
                try:
                    remote_socket.unlink()
                except FileNotFoundError:
                    pass
                remote_thread.join(timeout=1)
            self.assertFalse(config.local_socket.exists())

    def test_ssh_exit_is_reported_as_transport_unavailable_with_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = _write_fake_ssh(root, "fake-ssh-exit.py")
            config = self._config(root, fake)
            with self.assertRaises(SSHForwardError) as caught:
                SSHForward(config).start()
            self.assertEqual(caught.exception.status, "transport_unavailable")
            self.assertEqual(caught.exception.returncode, 23)
            self.assertIn("refused the channel", caught.exception.stderr)

    def test_startup_deadline_is_a_timeout_and_child_is_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = _write_fake_ssh(root, "fake-ssh-late.py")
            config = self._config(root, fake, startup_timeout_s=0.1)
            forward = SSHForward(config)
            with self.assertRaises(SSHForwardError) as caught:
                forward.start()
            self.assertEqual(caught.exception.status, "timeout")
            self.assertIsNotNone(forward.pid)
            self.assertFalse(config.local_socket.exists())

    def test_a_forward_that_dies_after_start_is_surfaceable_by_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = _write_fake_ssh(root, "fake-ssh.py")
            config = self._config(root, fake)
            forward = SSHForward(config).start()
            assert forward._process is not None  # test observes the local fake process
            forward._process.terminate()
            forward._process.wait(timeout=2)
            with self.assertRaises(SSHForwardError) as caught:
                forward.check()
            self.assertEqual(caught.exception.status, "transport_unavailable")
            forward.stop()

    def test_non_private_parent_is_rejected_before_spawning_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            fake = _write_fake_ssh(root, "fake-ssh.py")
            config = self._config(root, fake)
            with self.assertRaises(SSHForwardError) as caught:
                SSHForward(config).start()
            self.assertIn("private", str(caught.exception))

    def test_existing_path_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = _write_fake_ssh(root, "fake-ssh.py")
            existing = root / "sidecar.sock"
            existing.write_text("do not delete", encoding="utf-8")
            config = self._config(root, fake)
            with self.assertRaises(SSHForwardError):
                SSHForward(config).start()
            self.assertEqual(existing.read_text(encoding="utf-8"), "do not delete")

    def test_symlinked_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            fake = _write_fake_ssh(root, "fake-ssh.py")
            config = self._config(root, fake, local_socket=link / "sidecar.sock")
            with self.assertRaises(SSHForwardError) as caught:
                SSHForward(config).start()
            self.assertIn("symlink", str(caught.exception))

    def test_cleanup_does_not_unlink_a_replaced_socket_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = _write_fake_ssh(root, "fake-ssh.py")
            config = self._config(root, fake)
            forward = SSHForward(config).start()
            assert forward._process is not None
            forward._process.kill()
            forward._process.wait(timeout=2)
            replacement = root / "replacement.sock"
            # A real Unix socket gives the replacement a different inode and
            # models a supervisor taking ownership after the original exits.
            import socket

            replacement_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            replacement_listener.bind(str(replacement))
            old = config.local_socket
            old.unlink()
            replacement_listener.close()
            replacement.rename(old)
            forward.stop()
            self.assertTrue(old.exists())
            old.unlink()


if __name__ == "__main__":
    unittest.main()
