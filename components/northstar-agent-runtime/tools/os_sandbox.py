"""OS-level execution backends for governed command tools (Shell).

Two backends, one contract:

* **bwrap** (preferred) — bubblewrap with a read-only host view, a writable
  bind of the workspace, no network namespace, a seccomp-BPF denylist over
  escape primitives (``tools/seccomp.py``), and die-with-parent. This is the
  isolation level the threat model calls a *sandbox*.
* **process** (fallback) — a scrubbed subprocess with cwd pinned inside the
  workspace, resource limits, and process-group cleanup, plus the same
  seccomp-BPF denylist applied via a prctl wrapper (Linux only). This is *not*
  OS isolation: a determined command can still reach the rest of the host via
  absolute paths. Doctor and the Shell tool both say so out loud.

The runtime never invents a third, quieter mode. ``auto`` picks bwrap when the
binary exists and can start a throwaway probe; otherwise process. An operator
who asks for bwrap on a host without it gets a configuration error, not a
silent downgrade — a run advertised as sandboxed that quietly is not would be
the exact lie this project refuses to tell.

This module is importable without bwrap installed. Every public function is
pure or side-effect-bounded so the deterministic test suite can exercise the
process backend and the policy surface offline.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from tools.seccomp import SECCOMP_MODES, SeccompError, build_default_filter, prctl_loader_argv

#: Hard ceilings a single Shell invocation may not exceed. Operators may only
#: tighten these (via tool payload or run config), never widen past the runtime.
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 300_000
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_MAX_ARGV = 64
MAX_ARGV_BYTES = 32 * 1024
DEFAULT_MAX_ENV = 32

BACKENDS = ("auto", "bwrap", "process")


class SandboxError(RuntimeError):
    """The sandbox refused to start or enforce. Message is operator-facing."""


@dataclass(frozen=True)
class SandboxCapabilities:
    """What this host can actually offer. Doctor and init records both use it."""

    bwrap_path: str | None
    bwrap_usable: bool
    bwrap_detail: str
    process_available: bool = True
    preferred: str = "process"

    def as_dict(self) -> dict[str, Any]:
        return {
            "bwrap_path": self.bwrap_path,
            "bwrap_usable": self.bwrap_usable,
            "bwrap_detail": self.bwrap_detail,
            "process_available": self.process_available,
            "preferred": self.preferred,
            "isolation": "os" if self.preferred == "bwrap" and self.bwrap_usable else "process",
        }


@dataclass(frozen=True)
class SandboxRequest:
    """One command the sandbox is asked to run."""

    argv: tuple[str, ...]
    cwd: Path
    workspace: Path
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    env: Mapping[str, str] | None = None
    network: bool = False  # reserved: bwrap always unshares net today; True is refused
    seccomp: str = "auto"  # seccomp denylist: auto (bwrap only) | on (require) | off


@dataclass(frozen=True)
class SandboxResult:
    """Outcome of one sandboxed command. Always returned, never raised for exit≠0."""

    argv: tuple[str, ...]
    backend: str
    isolation: str  # "os" | "process"
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    detail: str = ""

    @property
    def ok(self) -> bool:
        return (not self.timed_out) and self.exit_code == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "backend": self.backend,
            "isolation": self.isolation,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_chars": len(self.stdout),
            "stderr_chars": len(self.stderr),
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "detail": self.detail,
        }

    def render(self) -> str:
        """Human/model-facing body: exit, streams, and an honest isolation line."""
        lines = [
            f"exit={self.exit_code if self.exit_code is not None else 'n/a'}"
            + (" timed_out=true" if self.timed_out else ""),
            f"backend={self.backend} isolation={self.isolation}",
        ]
        if self.detail:
            lines.append(f"note: {self.detail}")
        if self.stdout:
            lines.append("--- stdout ---")
            lines.append(self.stdout if not self.stdout.endswith("\n") else self.stdout.rstrip("\n"))
        if self.stderr:
            lines.append("--- stderr ---")
            lines.append(self.stderr if not self.stderr.endswith("\n") else self.stderr.rstrip("\n"))
        if not self.stdout and not self.stderr:
            lines.append("(no output)")
        if self.truncated:
            lines.append("[output truncated by the runtime sandbox cap]")
        return "\n".join(lines)


_CAP_CACHE: SandboxCapabilities | None = None


def reset_capabilities_cache() -> None:
    """Tests only: drop the cached probe so a fixture can re-run discovery."""
    global _CAP_CACHE
    _CAP_CACHE = None


def probe_capabilities(*, force: bool = False, bwrap_bin: str | None = None) -> SandboxCapabilities:
    """Discover what isolation this host can provide (cached after first call)."""
    global _CAP_CACHE
    if _CAP_CACHE is not None and not force:
        return _CAP_CACHE
    path = bwrap_bin or shutil.which("bwrap")
    usable = False
    detail = "bwrap not found on PATH"
    if path:
        try:
            # A real, empty sandbox is the only honest probe: --version alone does
            # not prove user namespaces or seccomp work on this kernel.
            completed = subprocess.run(
                [
                    path,
                    "--die-with-parent",
                    "--unshare-pid",
                    "--unshare-net",
                    "--ro-bind",
                    "/",
                    "/",
                    "--tmpfs",
                    "/tmp",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--chdir",
                    "/",
                    "true",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode == 0:
                usable = True
                detail = f"bwrap usable at {path}"
            else:
                err = (completed.stderr or completed.stdout or "").strip().splitlines()
                detail = f"bwrap at {path} failed probe: {(err[-1] if err else 'exit ' + str(completed.returncode))[:200]}"
        except (OSError, subprocess.TimeoutExpired) as error:
            detail = f"bwrap at {path} could not be probed: {error}"
    preferred = "bwrap" if usable else "process"
    caps = SandboxCapabilities(
        bwrap_path=path if path else None,
        bwrap_usable=usable,
        bwrap_detail=detail,
        preferred=preferred,
    )
    _CAP_CACHE = caps
    return caps


def resolve_backend(requested: str, *, capabilities: SandboxCapabilities | None = None) -> str:
    """Map ``auto|bwrap|process`` to the backend that will actually run."""
    choice = (requested or "auto").strip().lower()
    if choice not in BACKENDS:
        raise SandboxError(f"unknown sandbox backend {requested!r}; choose one of {', '.join(BACKENDS)}")
    caps = capabilities or probe_capabilities()
    if choice == "auto":
        return caps.preferred
    if choice == "bwrap" and not caps.bwrap_usable:
        raise SandboxError(
            f"sandbox backend 'bwrap' was requested but is not usable on this host ({caps.bwrap_detail}). "
            "Install bubblewrap, or pass --sandbox process and accept process-level isolation only"
        )
    return choice


def _scrubbed_env(extra: Mapping[str, str] | None, *, workspace: Path) -> dict[str, str]:
    """Environment the child may see: no parent secrets, no surprise PATH games."""
    path = os.environ.get("PATH") or "/usr/bin:/bin"
    lang = os.environ.get("LANG") or "C.UTF-8"
    env = {
        "PATH": path,
        "LANG": lang,
        "LC_ALL": lang,
        "HOME": str(workspace),
        "TMPDIR": str(workspace / ".northstar" / "tmp"),
        "NORTHSTAR_SANDBOX": "1",
    }
    if extra:
        if len(extra) > DEFAULT_MAX_ENV:
            raise SandboxError(f"env map exceeds {DEFAULT_MAX_ENV} entries")
        for key, value in extra.items():
            if not isinstance(key, str) or not key or any(ch in key for ch in "=/\x00"):
                raise SandboxError(f"invalid env key {key!r}")
            if not isinstance(value, str) or "\x00" in value:
                raise SandboxError(f"env {key!r} must be a string without NUL")
            # Never let a tool payload override the scrub markers or HOME escape.
            if key in {"HOME", "TMPDIR", "NORTHSTAR_SANDBOX", "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"}:
                raise SandboxError(f"env key {key!r} is reserved by the sandbox")
            env[key] = value
    return env


def _validate_request(request: SandboxRequest) -> None:
    if not request.argv:
        raise SandboxError("argv must not be empty")
    if len(request.argv) > DEFAULT_MAX_ARGV:
        raise SandboxError(f"argv exceeds {DEFAULT_MAX_ARGV} entries")
    total = 0
    for item in request.argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise SandboxError("each argv entry must be a non-empty string without NUL")
        total += len(item)
    if total > MAX_ARGV_BYTES:
        raise SandboxError(f"argv total size exceeds {MAX_ARGV_BYTES} bytes")
    if request.network:
        raise SandboxError(
            "network=true is not offered yet: the bwrap backend always unshares the network "
            "namespace, and the process backend cannot honestly promise egress control"
        )
    if not isinstance(request.timeout_ms, int) or not (1 <= request.timeout_ms <= MAX_TIMEOUT_MS):
        raise SandboxError(f"timeout_ms must be an integer in 1..{MAX_TIMEOUT_MS}")
    if not isinstance(request.max_output_bytes, int) or not (1 <= request.max_output_bytes <= MAX_OUTPUT_BYTES):
        raise SandboxError(f"max_output_bytes must be an integer in 1..{MAX_OUTPUT_BYTES}")
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    try:
        cwd.relative_to(workspace)
    except ValueError as error:
        raise SandboxError(f"cwd {cwd} escapes workspace {workspace}") from error
    if not cwd.is_dir():
        raise SandboxError(f"cwd is not a directory: {cwd}")
    if not workspace.is_dir():
        raise SandboxError(f"workspace is not a directory: {workspace}")
    seccomp = (request.seccomp or "auto").strip().lower()
    if seccomp not in SECCOMP_MODES:
        raise SandboxError(
            f"unknown seccomp mode {request.seccomp!r}; choose one of {', '.join(SECCOMP_MODES)}"
        )


def _read_capped(stream: Any, limit: int) -> tuple[bytes, bool]:
    data = stream.read(limit + 1) if stream is not None else b""
    if data is None:
        data = b""
    truncated = len(data) > limit
    return data[:limit], truncated


def _run_popen(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_ms: int,
    max_output_bytes: int,
    backend: str,
    isolation: str,
    detail: str = "",
    pass_fds: Sequence[int] = (),
) -> SandboxResult:
    """Shared runner: process-group kill on timeout, capped pipes, no shell=True."""
    # Ensure TMPDIR exists for the child (workspace-scoped).
    tmp = Path(env.get("TMPDIR") or (cwd / ".northstar" / "tmp"))
    try:
        tmp.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        pass

    started = time.monotonic()
    popen_kwargs: dict[str, Any] = {}
    if pass_fds:
        popen_kwargs["pass_fds"] = tuple(pass_fds)
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # own process group → TERM/KILL the tree
            close_fds=True,
            **popen_kwargs,
        )
    except OSError as error:
        return SandboxResult(
            argv=tuple(argv),
            backend=backend,
            isolation=isolation,
            exit_code=None,
            timed_out=False,
            stdout="",
            stderr="",
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=f"failed to start: {error}",
        )

    timed_out = False
    try:
        raw_out, raw_err = proc.communicate(timeout=timeout_ms / 1000.0)
        truncated = False
        if raw_out is None:
            raw_out = b""
        if raw_err is None:
            raw_err = b""
        if len(raw_out) > max_output_bytes:
            raw_out = raw_out[:max_output_bytes]
            truncated = True
        if len(raw_err) > max_output_bytes:
            raw_err = raw_err[:max_output_bytes]
            truncated = True
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        truncated = False
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            raw_out, raw_err = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                raw_out, raw_err = proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                raw_out, raw_err = b"", b""
        if raw_out is None:
            raw_out = b""
        if raw_err is None:
            raw_err = b""
        if len(raw_out) > max_output_bytes:
            raw_out = raw_out[:max_output_bytes]
            truncated = True
        if len(raw_err) > max_output_bytes:
            raw_err = raw_err[:max_output_bytes]
            truncated = True
        exit_code = proc.returncode

    def decode(blob: bytes) -> str:
        return blob.decode("utf-8", "replace")

    note = detail
    if timed_out:
        note = (note + "; " if note else "") + f"killed after {timeout_ms}ms (process group TERM→KILL)"

    return SandboxResult(
        argv=tuple(argv),
        backend=backend,
        isolation=isolation,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=decode(raw_out),
        stderr=decode(raw_err),
        duration_ms=int((time.monotonic() - started) * 1000),
        truncated=truncated,
        detail=note,
    )


def _bwrap_argv(request: SandboxRequest, *, bwrap_path: str, seccomp_fd: int | None = None) -> list[str]:
    """Build a conservative bubblewrap command line around the user argv."""
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    # Host paths the child needs to actually execute anything useful. Bound
    # read-only; the workspace is the only writable bind.
    ro_binds = []
    for host_path in ("/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc/resolv.conf", "/etc/ssl", "/etc/passwd", "/etc/group"):
        if Path(host_path).exists():
            ro_binds.extend(["--ro-bind", host_path, host_path])
    seccomp_args: list[str] = []
    if seccomp_fd is not None:
        # bwrap reads the BPF program from this fd at exec time; the caller
        # keeps it open via Popen(pass_fds=[...]).
        seccomp_args = ["--seccomp", str(seccomp_fd)]
    argv = [
        bwrap_path,
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        *seccomp_args,
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/var",
        "--dir",
        "/run",
        *ro_binds,
        "--bind",
        str(workspace),
        str(workspace),
        "--chdir",
        str(cwd),
        "--",
        *request.argv,
    ]
    return argv


def run_sandboxed(
    request: SandboxRequest,
    *,
    backend: str = "auto",
    capabilities: SandboxCapabilities | None = None,
) -> SandboxResult:
    """Run ``request`` under the resolved backend. Never uses ``shell=True``."""
    _validate_request(request)
    caps = capabilities or probe_capabilities()
    chosen = resolve_backend(backend, capabilities=caps)
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    env = _scrubbed_env(request.env, workspace=workspace)
    seccomp_mode = (request.seccomp or "auto").strip().lower()

    if chosen == "bwrap":
        assert caps.bwrap_path  # resolve_backend guaranteed usable
        seccomp_fd: int | None = None
        seccomp_file = None
        pass_fds: list[int] = []
        detail = "network namespace unshared; workspace is the only writable bind"
        if seccomp_mode != "off":
            # The BPF denylist rides into bwrap on an inherited fd
            # (``bwrap --seccomp FD``). A temp file under the workspace tmp dir
            # keeps the bytes off any shared location.
            tmpdir = workspace / ".northstar" / "tmp"
            tmpdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            seccomp_file = tempfile.NamedTemporaryFile(
                prefix="seccomp-", suffix=".bpf", dir=str(tmpdir), delete=False
            )
            try:
                seccomp_file.write(build_default_filter())
                seccomp_file.flush()
                seccomp_fd = seccomp_file.fileno()
                pass_fds.append(seccomp_fd)
                detail += "; seccomp denylist active (escape primitives -> EPERM)"
            except Exception:
                seccomp_file.close()
                raise
        try:
            wrapped = _bwrap_argv(request, bwrap_path=caps.bwrap_path, seccomp_fd=seccomp_fd)
            result = _run_popen(
                wrapped,
                cwd=cwd,  # bwrap --chdir is authoritative; cwd here is best-effort
                env=env,
                timeout_ms=request.timeout_ms,
                max_output_bytes=request.max_output_bytes,
                backend="bwrap",
                isolation="os",
                detail=detail,
                pass_fds=pass_fds,
            )
        finally:
            if seccomp_file is not None:
                name = seccomp_file.name
                seccomp_file.close()
                try:
                    os.unlink(name)
                except OSError:
                    pass
        return result

    if seccomp_mode == "on" and not sys.platform.startswith("linux"):
        # No silent downgrade: the operator required the filter, and this
        # platform cannot apply one on any backend.
        raise SandboxError(
            f"seccomp='on' requires a platform that can load a BPF filter "
            f"(this host is {sys.platform})."
        )
    base_detail = (
        "process backend: cwd pinned and env scrubbed, but the host filesystem "
        "and network are still reachable — install bubblewrap for OS isolation"
    )
    exec_argv: Sequence[str] = request.argv
    if seccomp_mode != "off" and sys.platform.startswith("linux"):
        # The filter rides in on a python wrapper that prctl()s it before
        # exec (see tools/seccomp.py: no preexec_fn, so no fork-in-threads
        # hazard). The audit trail keeps the original argv; the wrapper is
        # an implementation detail named in `detail`.
        python = shutil.which("python3") or sys.executable
        exec_argv = prctl_loader_argv(request.argv, python=python)
        detail = base_detail + "; seccomp denylist active (prctl, EPERM on deny)"
    else:
        detail = base_detail + "; seccomp not applied"
        if seccomp_mode != "off":
            detail += f" ({sys.platform} cannot load a BPF filter)"
    result = _run_popen(
        exec_argv,
        cwd=cwd,
        env=env,
        timeout_ms=request.timeout_ms,
        max_output_bytes=request.max_output_bytes,
        backend="process",
        isolation="process",
        detail=detail,
    )
    # The audit trail records what the caller asked for, not the wrapper.
    return replace(result, argv=request.argv)


__all__ = [
    "BACKENDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_MS",
    "MAX_OUTPUT_BYTES",
    "MAX_TIMEOUT_MS",
    "SECCOMP_MODES",
    "SandboxCapabilities",
    "SandboxError",
    "SandboxRequest",
    "SandboxResult",
    "probe_capabilities",
    "reset_capabilities_cache",
    "resolve_backend",
    "run_sandboxed",
]
