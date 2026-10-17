"""SSH forwarding for a private Northstar Sidecar Unix socket.

This module owns the channel lifecycle only. The Sidecar JSON-lines protocol,
Run Contract, host authorization and handoff grants remain unchanged.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

DEFAULT_REMOTE_SOCKET = "/var/run/northstar-codex/sidecar.sock"
DEFAULT_LOCAL_SOCKET_NAME = "sidecar.sock"
DEFAULT_CONTROL_SOCKET_NAME = "ssh-control"
DEFAULT_READY_TIMEOUT_SECONDS = 15.0
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10.0
DEFAULT_SERVER_ALIVE_INTERVAL_SECONDS = 15
DEFAULT_SERVER_ALIVE_COUNT_MAX = 3
FORWARD_GRACE_SECONDS = 1.0


class SSHForwardError(RuntimeError):
    """Base error for the SSH channel lifecycle."""


class SSHForwardStartError(SSHForwardError):
    """The SSH process could not be started or exited during startup."""


class SSHForwardTimeout(SSHForwardError):
    """The local forwarded socket did not become ready in time."""


class SSHForwardUnavailable(SSHForwardError):
    """The SSH forward exited or became unavailable after startup."""


def _validate_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or any(char.isspace() for char in value):
        raise ValueError(f"{field} must be a non-empty value without whitespace or NUL bytes")
    return value


def _validate_socket_path(path: Path, field: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    if path.name != DEFAULT_LOCAL_SOCKET_NAME:
        raise ValueError(f"{field} must end with {DEFAULT_LOCAL_SOCKET_NAME!r}")
    return path


@dataclass(frozen=True)
class SSHForwardConfig:
    """Validated configuration for one private SSH Unix-socket forward."""

    worker: str
    remote_socket: str = DEFAULT_REMOTE_SOCKET
    local_state_dir: Path = field(default_factory=lambda: Path.home() / ".local" / "state" / "northstar" / "remote")
    local_socket_name: str = DEFAULT_LOCAL_SOCKET_NAME
    control_socket_name: str = DEFAULT_CONTROL_SOCKET_NAME
    ssh_binary: str = "ssh"
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    ready_timeout_seconds: float = DEFAULT_READY_TIMEOUT_SECONDS
    server_alive_interval_seconds: int = DEFAULT_SERVER_ALIVE_INTERVAL_SECONDS
    server_alive_count_max: int = DEFAULT_SERVER_ALIVE_COUNT_MAX
    extra_options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_text(self.worker, "worker")
        _validate_text(self.ssh_binary, "ssh_binary")
        if not self.remote_socket.startswith("/") or "\x00" in self.remote_socket or any(
            char.isspace() for char in self.remote_socket
        ):
            raise ValueError("remote_socket must be an absolute path without whitespace or NUL bytes")
        if self.local_socket_name != DEFAULT_LOCAL_SOCKET_NAME:
            raise ValueError(f"local_socket_name must be {DEFAULT_LOCAL_SOCKET_NAME!r}")
        _validate_text(self.control_socket_name, "control_socket_name")
        if self.control_socket_name == self.local_socket_name:
            raise ValueError("control_socket_name must differ from local_socket_name")
        if self.connect_timeout_seconds <= 0 or self.ready_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")
        if self.server_alive_interval_seconds <= 0 or self.server_alive_count_max <= 0:
            raise ValueError("SSH keepalive settings must be positive")
        if not isinstance(self.extra_options, tuple):
            raise ValueError("extra_options must be a tuple")
        for option in self.extra_options:
            _validate_text(option, "extra SSH option")

    @property
    def local_socket(self) -> Path:
        return _validate_socket_path(Path(self.local_state_dir) / self.local_socket_name, "local_socket")

    @property
    def control_socket(self) -> Path:
        return Path(self.local_state_dir) / self.control_socket_name

    def argv(self) -> tuple[str, ...]:
        """Return the SSH argv; callers must pass it with ``shell=False``."""
        return (
            self.ssh_binary,
            "-N",
            "-M",
            "-S",
            str(self.control_socket),
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            f"ConnectTimeout={int(self.connect_timeout_seconds)}",
            "-o",
            f"ServerAliveInterval={self.server_alive_interval_seconds}",
            "-o",
            f"ServerAliveCountMax={self.server_alive_count_max}",
            *self.extra_options,
            "-L",
            f"{self.local_socket}:{self.remote_socket}",
            self.worker,
        )


class SSHSocketForward:
    """Manage one SSH process forwarding a remote Sidecar Unix socket."""

    def __init__(self, config: SSHForwardConfig, *, popen=subprocess.Popen) -> None:
        self.config = config
        self._popen = popen
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def local_socket(self) -> Path:
        return self.config.local_socket

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        return self._process

    def start(self) -> "SSHSocketForward":
        if self._process is not None:
            raise SSHForwardError("SSH forward is already started")
        state = Path(self.config.local_state_dir)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state, 0o700)
        if self.local_socket.exists():
            if self.local_socket.is_socket():
                raise SSHForwardStartError(f"local socket already exists: {self.local_socket}")
            raise SSHForwardStartError(f"local socket path is occupied: {self.local_socket}")
        try:
            self._process = self._popen(
                list(self.config.argv()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
                shell=False,
            )
        except OSError as error:
            raise SSHForwardStartError(f"could not start SSH forward: {error}") from error
        return self

    def is_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _exit_detail(self) -> str:
        process = self._process
        if process is None:
            return "SSH forward is not started"
        code = process.poll()
        if code is None:
            return "SSH forward is running"
        stderr = b""
        if process.stderr is not None:
            try:
                stderr = process.stderr.read() or b""
            except OSError:
                pass
        detail = stderr.decode("utf-8", "replace").strip()
        return f"SSH forward exited with status {code}" + (f": {detail[:500]}" if detail else "")

    def wait_ready(self, *, timeout_seconds: float | None = None) -> Path:
        if self._process is None:
            raise SSHForwardError("SSH forward has not been started")
        deadline = time.monotonic() + (timeout_seconds or self.config.ready_timeout_seconds)
        while time.monotonic() < deadline:
            if not self.is_alive():
                raise SSHForwardUnavailable(self._exit_detail())
            if self.local_socket.is_socket() and self._can_connect():
                return self.local_socket
            time.sleep(0.05)
        self.close()
        raise SSHForwardTimeout(f"forwarded socket did not become ready: {self.local_socket}")

    def _can_connect(self) -> bool:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(0.2)
        try:
            connection.connect(str(self.local_socket))
            return True
        except OSError:
            return False
        finally:
            connection.close()

    def close(self) -> None:
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    process.terminate()
                except OSError:
                    pass
            try:
                process.wait(timeout=FORWARD_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        process.kill()
                    except OSError:
                        pass
                process.wait()
        if process is not None and process.stderr is not None:
            try:
                process.stderr.close()
            except OSError:
                pass
        try:
            if self.local_socket.is_socket():
                self.local_socket.unlink()
        except OSError:
            pass

    def __enter__(self) -> "SSHSocketForward":
        return self.start()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
