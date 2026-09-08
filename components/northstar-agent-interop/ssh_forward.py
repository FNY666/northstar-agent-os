"""Bounded SSH local-socket forwarding for the Profile A worker channel.

The remote-worker design deliberately reuses the sidecar's JSON-lines Unix
socket instead of inventing a second protocol.  This module owns only the
orchestrator-side channel lifecycle:

* construct an ``ssh -N -T`` command with strict host-key and no-agent
  forwarding defaults;
* refuse an unsafe or already-existing local socket path;
* wait until the forwarded Unix socket is connectable;
* surface an SSH exit or startup deadline as a typed transport error; and
* terminate the SSH process group and remove only the socket inode this
  instance created.

It does not execute a remote shell, copy a workspace, mint grants, or claim
that a real worker has been exercised.  Tests use a local fake SSH executable;
a real host-key check and end-to-end canary remain operator responsibilities.
"""
from __future__ import annotations

import math
import os
import signal
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SOCKET_FILENAME = "sidecar.sock"
MAX_UNIX_SOCKET_PATH_BYTES = 107
MAX_DESTINATION_CHARS = 512
MAX_STDERR_BYTES = 16_384


def _as_path(value: str | os.PathLike[str], field: str) -> Path:
    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a filesystem path") from error
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    encoded = os.fsencode(str(path))
    if len(encoded) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise ValueError(f"{field} is too long for a Unix socket path")
    if path.name != SOCKET_FILENAME:
        raise ValueError(f"{field} must be named {SOCKET_FILENAME}")
    return path


def _validate_destination(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_DESTINATION_CHARS:
        raise ValueError("destination must be a non-empty bounded SSH destination")
    if any(char.isspace() or char == "\x00" for char in value):
        raise ValueError("destination must not contain whitespace or NUL")
    if value.startswith("-"):
        raise ValueError("destination must not begin with '-' (SSH option injection)")
    return value


def _validate_positive(value: float | int, field: str, *, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a positive number") from error
    if number <= 0 or number > maximum:
        raise ValueError(f"{field} must be greater than zero and at most {maximum:g}")
    return number


def _validate_count(value: int, field: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{field} must be an integer between 1 and {maximum}")
    return value


@dataclass(frozen=True)
class SSHForwardConfig:
    """Immutable inputs for one SSH local Unix-socket forward.

    ``local_socket`` and its parent must already exist under a private
    directory owned by the current user.  Requiring the directory up front is
    intentional: the helper never creates a broadly accessible path or
    changes permissions on an operator-owned directory silently.
    """

    destination: str
    remote_socket: str | os.PathLike[str]
    local_socket: str | os.PathLike[str]
    ssh_binary: str = "ssh"
    known_hosts: str | os.PathLike[str] | None = None
    identity_file: str | os.PathLike[str] | None = None
    connect_timeout_s: float = 10.0
    server_alive_interval_s: float = 5.0
    server_alive_count_max: int = 3
    startup_timeout_s: float = 10.0
    stop_grace_s: float = 2.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "destination", _validate_destination(self.destination))
        object.__setattr__(self, "remote_socket", _as_path(self.remote_socket, "remote_socket"))
        object.__setattr__(self, "local_socket", _as_path(self.local_socket, "local_socket"))
        if not isinstance(self.ssh_binary, str) or not self.ssh_binary or any(
            char.isspace() or char == "\x00" for char in self.ssh_binary
        ):
            raise ValueError("ssh_binary must be a non-empty executable name or absolute path")
        object.__setattr__(
            self,
            "connect_timeout_s",
            _validate_positive(self.connect_timeout_s, "connect_timeout_s", maximum=300.0),
        )
        object.__setattr__(
            self,
            "server_alive_interval_s",
            _validate_positive(self.server_alive_interval_s, "server_alive_interval_s", maximum=300.0),
        )
        object.__setattr__(
            self,
            "server_alive_count_max",
            _validate_count(self.server_alive_count_max, "server_alive_count_max", maximum=20),
        )
        object.__setattr__(
            self,
            "startup_timeout_s",
            _validate_positive(self.startup_timeout_s, "startup_timeout_s", maximum=300.0),
        )
        object.__setattr__(
            self,
            "stop_grace_s",
            _validate_positive(self.stop_grace_s, "stop_grace_s", maximum=60.0),
        )
        if self.known_hosts is not None:
            object.__setattr__(self, "known_hosts", _absolute_file_path(self.known_hosts, "known_hosts"))
        if self.identity_file is not None:
            object.__setattr__(self, "identity_file", _absolute_file_path(self.identity_file, "identity_file"))

    @property
    def command(self) -> tuple[str, ...]:
        """Return the argv that will be passed to ``Popen(shell=False)``."""
        return build_ssh_command(self)


def _absolute_file_path(value: str | os.PathLike[str], field: str) -> Path:
    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a filesystem path") from error
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    return path


def build_ssh_command(config: SSHForwardConfig) -> tuple[str, ...]:
    """Build a non-shell SSH argv with the channel's safety defaults."""
    command: list[str] = [
        config.ssh_binary,
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"ServerAliveInterval={math.ceil(config.server_alive_interval_s)}",
        "-o",
        f"ServerAliveCountMax={config.server_alive_count_max}",
        "-o",
        f"ConnectTimeout={math.ceil(config.connect_timeout_s)}",
    ]
    if config.known_hosts is not None:
        command.extend(("-o", f"UserKnownHostsFile={config.known_hosts}"))
    if config.identity_file is not None:
        command.extend(("-i", str(config.identity_file), "-o", "IdentitiesOnly=yes"))
    command.extend(("-L", f"{config.local_socket}:{config.remote_socket}", config.destination))
    return tuple(command)


class SSHForwardError(RuntimeError):
    """An expected channel failure with a contract-level status."""

    def __init__(
        self,
        message: str,
        *,
        status: str = "transport_unavailable",
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.returncode = returncode
        self.stderr = stderr


class SSHForward:
    """Start and supervise one bounded SSH local-socket forward."""

    def __init__(self, config: SSHForwardConfig) -> None:
        self.config = config
        self._process: subprocess.Popen[bytes] | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._stderr_parts: list[bytes] = []
        self._stderr_size = 0
        self._stderr_lock = threading.Lock()
        self._stderr_thread: threading.Thread | None = None
        self._started = False
        self._ready = False

    @property
    def command(self) -> tuple[str, ...]:
        return self.config.command

    @property
    def pid(self) -> int | None:
        return None if self._process is None else self._process.pid

    @property
    def ready(self) -> bool:
        return self._ready and self._process is not None and self._process.poll() is None

    @property
    def stderr(self) -> str:
        with self._stderr_lock:
            raw = b"".join(self._stderr_parts)
        return raw.decode("utf-8", errors="replace").strip()

    def start(self) -> "SSHForward":
        """Spawn SSH and wait until the local socket accepts a connection."""
        if self._started:
            raise RuntimeError("SSH forward can only be started once")
        self._started = True
        self._validate_local_directory()
        if self.config.local_socket.exists() or self.config.local_socket.is_symlink():
            raise SSHForwardError(
                f"refusing to overwrite existing local socket path {self.config.local_socket}",
                status="transport_unavailable",
            )
        if os.name != "posix":
            raise SSHForwardError("Profile A SSH forwarding requires a POSIX host", status="transport_unavailable")
        try:
            self._process = subprocess.Popen(
                self.command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                shell=False,
            )
        except OSError as error:
            raise SSHForwardError(f"could not start SSH forward: {error}", status="transport_unavailable") from error
        assert self._process.stderr is not None
        self._stderr_thread = threading.Thread(
            target=self._capture_stderr,
            args=(self._process.stderr,),
            name="northstar-ssh-forward-stderr",
            daemon=True,
        )
        self._stderr_thread.start()
        try:
            self._wait_until_ready()
        except SSHForwardError:
            self.stop()
            raise
        self._ready = True
        return self

    def check(self) -> None:
        """Raise if the forward exited or its local socket is no longer usable."""
        process = self._require_process()
        returncode = process.poll()
        if returncode is not None:
            raise self._exit_error(returncode)
        if not self._can_connect(timeout_s=0.2):
            raise SSHForwardError(
                f"forwarded socket {self.config.local_socket} is not accepting connections",
                status="transport_unavailable",
            )

    def stop(self) -> int | None:
        """Stop the SSH process group and clean up only this instance's socket."""
        process = self._process
        if process is None:
            self._cleanup_socket()
            return None
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=self.config.stop_grace_s)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=max(0.2, self.config.stop_grace_s))
        returncode = process.poll()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=0.2)
        if process.stderr is not None:
            process.stderr.close()
        self._cleanup_socket()
        self._ready = False
        return returncode

    def wait_for_exit(self, timeout_s: float | None = None) -> int:
        """Wait for SSH to exit; a live forward times out rather than hanging."""
        process = self._require_process()
        try:
            return process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            raise SSHForwardError(
                "SSH forward did not exit before the deadline",
                status="timeout",
            ) from None

    def __enter__(self) -> "SSHForward":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()

    def _require_process(self) -> subprocess.Popen[bytes]:
        if self._process is None:
            raise RuntimeError("SSH forward has not been started")
        return self._process

    def _validate_local_directory(self) -> None:
        parent = self.config.local_socket.parent
        if parent.is_symlink():
            raise SSHForwardError(f"local socket parent must not be a symlink: {parent}")
        try:
            info = parent.stat()
        except OSError as error:
            raise SSHForwardError(f"local socket directory cannot be inspected: {error}") from error
        if not stat.S_ISDIR(info.st_mode):
            raise SSHForwardError(f"local socket parent is not a directory: {parent}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise SSHForwardError(f"local socket directory is not owned by the current user: {parent}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SSHForwardError(f"local socket directory must be private (mode 0700): {parent}")

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.config.startup_timeout_s
        while time.monotonic() < deadline:
            process = self._require_process()
            returncode = process.poll()
            if returncode is not None:
                raise self._exit_error(returncode)
            if self.config.local_socket.exists():
                try:
                    info = self.config.local_socket.stat()
                    if stat.S_ISSOCK(info.st_mode):
                        self._socket_identity = (info.st_dev, info.st_ino)
                        if self._can_connect(timeout_s=0.2):
                            return
                except OSError:
                    pass
            time.sleep(0.05)
        raise SSHForwardError(
            f"SSH forward did not publish a connectable socket within {self.config.startup_timeout_s:g}s",
            status="timeout",
            stderr=self.stderr,
        )

    def _can_connect(self, *, timeout_s: float) -> bool:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_s)
            sock.connect(str(self.config.local_socket))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _exit_error(self, returncode: int) -> SSHForwardError:
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=0.2)
        detail = self.stderr
        suffix = f": {detail}" if detail else ""
        return SSHForwardError(
            f"SSH forward exited with status {returncode}{suffix}",
            status="transport_unavailable",
            returncode=returncode,
            stderr=detail,
        )

    def _capture_stderr(self, stream: object) -> None:
        # ``Popen.stderr`` is a BufferedReader, but keeping this helper typed as
        # object lets the lifecycle remain easy to substitute in unit tests.
        read = getattr(stream, "read")
        while True:
            chunk = read(4096)
            if not chunk:
                return
            with self._stderr_lock:
                remaining = MAX_STDERR_BYTES - self._stderr_size
                if remaining > 0:
                    self._stderr_parts.append(bytes(chunk[:remaining]))
                    self._stderr_size += min(len(chunk), remaining)

    def _cleanup_socket(self) -> None:
        path = self.config.local_socket
        if self._socket_identity is None:
            return
        try:
            info = path.stat()
        except OSError:
            self._socket_identity = None
            return
        if (info.st_dev, info.st_ino) != self._socket_identity or not stat.S_ISSOCK(info.st_mode):
            return
        try:
            path.unlink()
        except OSError:
            return
        self._socket_identity = None


__all__ = ["SSHForward", "SSHForwardConfig", "SSHForwardError", "build_ssh_command"]
