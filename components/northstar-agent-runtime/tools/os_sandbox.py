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

import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from tools.capdrop import (
    CapDropError,
    bwrap_capability_args,
    capdrop_loader_argv,
    parse_whitelist,
    summarize_report,
)
from tools.sandbox import (
    LANDLOCK_MODES,
    default_profile,
    landlock_loader_argv,
    landlock_supported,
)
from tools.seccomp import SECCOMP_MODES, SeccompError, build_default_filter, prctl_loader_argv
from tools.pledge import (
    PledgeContext,
    PledgeError,
    PledgeViolation,
    enforcement_report,
    filesystem_rules,
    pledge_loader_argv,
    validate_promises,
)

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
    bwrap_cap_drop: bool = False
    process_available: bool = True
    preferred: str = "process"

    def as_dict(self) -> dict[str, Any]:
        return {
            "bwrap_path": self.bwrap_path,
            "bwrap_usable": self.bwrap_usable,
            "bwrap_detail": self.bwrap_detail,
            "bwrap_cap_drop": self.bwrap_cap_drop,
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
    #: Linux capability whitelist for the tool-effect child. ``()`` (the
    #: default) is deny-all; ``None`` disables the launcher entirely
    #: (operator escape hatch — the Shell tool only passes None when the
    #: operator configured ``--capdrop off``).
    capdrop_whitelist: tuple[str, ...] | None = ()
    landlock: str = "auto"  # landlock path allowlist (process backend, Linux):
    # auto (apply when the kernel supports it, degrade loudly to seccomp-only)
    # | on (require; refuse without Landlock) | off. Tighten-only per call.
    pledges: tuple[str, ...] | None = None  # pledge-style promise set; None = no pledge layer


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
    #: Audit report from the capability-drop launcher (process backend,
    #: Linux only): whitelist, before/after capability sets, per-operation
    #: results. ``None`` when the launcher did not run.
    capdrop: dict[str, Any] | None = None

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
            "capdrop": self.capdrop,
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
    cap_drop = False
    if usable and path:
        # bwrap(1) --cap-drop/--cap-add exist on modern bubblewrap; probe the
        # binary's own help rather than assuming the version.
        try:
            help_out = subprocess.run(
                [path, "--help"], capture_output=True, text=True, timeout=5, check=False
            )
            cap_drop = "--cap-drop" in (help_out.stdout or "")
        except (OSError, subprocess.TimeoutExpired):
            cap_drop = False
    preferred = "bwrap" if usable else "process"
    caps = SandboxCapabilities(
        bwrap_path=path if path else None,
        bwrap_usable=usable,
        bwrap_detail=detail,
        bwrap_cap_drop=cap_drop,
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
    if request.capdrop_whitelist is not None:
        try:
            whitelist = parse_whitelist(request.capdrop_whitelist)
        except CapDropError as error:
            raise SandboxError(f"invalid capdrop whitelist: {error}") from error
        if whitelist and not sys.platform.startswith("linux"):
            raise SandboxError(
                "a capdrop whitelist requires Linux (capset/prctl); "
                f"this host is {sys.platform}"
            )
    landlock = (request.landlock or "auto").strip().lower()
    if landlock not in LANDLOCK_MODES:
        raise SandboxError(
            f"unknown landlock mode {request.landlock!r}; choose one of {', '.join(LANDLOCK_MODES)}"
        )
    if request.pledges is not None:
        try:
            validate_promises(request.pledges)
        except PledgeError as error:
            raise SandboxError(f"invalid pledges: {error}") from error


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
    truncated = False
    output_limited = False
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    streams = (("stdout", proc.stdout), ("stderr", proc.stderr))
    for name, stream in streams:
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

    deadline = started + timeout_ms / 1000.0
    stop_reason = ""
    term_deadline: float | None = None
    kill_deadline: float | None = None
    kill_sent = False

    def signal_group(sig: int) -> None:
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    try:
        while True:
            now = time.monotonic()
            if not stop_reason and now >= deadline:
                timed_out = True
                stop_reason = "timeout"
                signal_group(signal.SIGTERM)
                term_deadline = now + 2.0
            elif stop_reason and not kill_sent and term_deadline is not None and now >= term_deadline:
                signal_group(signal.SIGKILL)
                kill_sent = True
                kill_deadline = now + 1.0
            elif kill_sent and kill_deadline is not None and now >= kill_deadline:
                break

            if proc.poll() is not None and not selector.get_map():
                if stop_reason and not kill_sent:
                    # The group may still contain a child that closed both pipes
                    # and ignored TERM after the original process exited.
                    signal_group(signal.SIGKILL)
                break
            wait_for = 0.05
            if not stop_reason:
                wait_for = min(wait_for, max(0.0, deadline - now))
            elif not kill_sent and term_deadline is not None:
                wait_for = min(wait_for, max(0.0, term_deadline - now))
            elif kill_deadline is not None:
                wait_for = min(wait_for, max(0.0, kill_deadline - now))

            ready = selector.select(wait_for) if selector.get_map() else ()
            if not ready:
                if not selector.get_map():
                    time.sleep(wait_for)
                continue
            for key, _mask in ready:
                stream = key.fileobj
                name = key.data
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer = captured[name]
                remaining = max_output_bytes - len(buffer)
                if len(chunk) > remaining:
                    if remaining > 0:
                        buffer.extend(chunk[:remaining])
                    truncated = True
                    if not stop_reason:
                        output_limited = True
                        stop_reason = "output_limit"
                        signal_group(signal.SIGTERM)
                        term_deadline = time.monotonic() + 2.0
                else:
                    buffer.extend(chunk)
    finally:
        selector.close()
        for _name, stream in streams:
            if stream is not None and not stream.closed:
                stream.close()

    if proc.poll() is None:
        signal_group(signal.SIGKILL)
    try:
        exit_code = proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        exit_code = proc.poll()
    raw_out = bytes(captured["stdout"])
    raw_err = bytes(captured["stderr"])

    def decode(blob: bytes) -> str:
        return blob.decode("utf-8", "replace")

    note = detail
    if timed_out:
        note = (note + "; " if note else "") + f"killed after {timeout_ms}ms (process group TERM→KILL)"
    elif output_limited:
        note = (note + "; " if note else "") + "output cap reached; process group terminated (TERM→KILL)"

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


def _minimal_identity_files() -> tuple[str, str]:
    """Synthesize minimal /etc/passwd and /etc/group contents for the sandbox.

    Only the invoking uid/gid gets an entry; every other host user stays
    invisible inside the sandbox (threat-model residual risk #2). The current
    user's name, home and shell are preserved verbatim, so getpwuid/getpwnam,
    whoami, id and git keep working exactly as outside; enumeration
    (getpwent) simply sees one user. ``pwd``/``grp`` are imported locally so
    this module still imports on platforms without them.
    """
    import grp
    import pwd

    uid, gid = os.getuid(), os.getgid()
    try:
        entry = pwd.getpwuid(uid)
        user, home, shell = entry.pw_name, entry.pw_dir, entry.pw_shell or "/bin/sh"
    except KeyError:
        # NSS-backed user (sssd/LDAP) with no file entry: the numeric ids are
        # still everything a tool needs to resolve the current user.
        user, home, shell = f"user{uid}", "/", "/bin/sh"
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = f"group{gid}"
    passwd = f"{user}:x:{uid}:{gid}::{home}:{shell}\n"
    groups = f"{group}:x:{gid}:\n"
    return passwd, groups


def _bwrap_argv(
    request: SandboxRequest,
    *,
    bwrap_path: str,
    seccomp_fd: int | None = None,
    passwd_path: str | None = None,
    group_path: str | None = None,
    capdrop_whitelist: tuple[str, ...] | None = None,
    cap_drop_supported: bool = False,
) -> list[str]:
    """Build a conservative bubblewrap command line around the user argv."""
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    # Pledge enforcement at the mount layer: a declared promise set without
    # wpath/cpath turns the workspace bind read-only. The semantic layer
    # (PledgeContext.require) fails closed too; this is defense in depth.
    pledges = frozenset(request.pledges or ())
    workspace_bind = "--bind"
    if request.pledges is not None and not ({"wpath", "cpath"} & pledges):
        workspace_bind = "--ro-bind"
    # Host paths the child needs to actually execute anything useful. Bound
    # read-only; the workspace is the only writable bind.
    #
    # Deliberately NOT bound: /etc/resolv.conf and /etc/ssl — the network
    # namespace is always unshared (network=true is refused), so nothing
    # inside can do DNS or TLS anyway, and resolv.conf leaks the operator's
    # internal DNS layout; the real /etc/passwd and /etc/group — replaced by
    # single-user synthetic files (see _minimal_identity_files) so the other
    # host users stay invisible.
    ro_binds = []
    for host_path in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
        if Path(host_path).exists():
            ro_binds.extend(["--ro-bind", host_path, host_path])
    identity_binds: list[str] = []
    if passwd_path is not None:
        identity_binds.extend(["--ro-bind", passwd_path, "/etc/passwd"])
    if group_path is not None:
        identity_binds.extend(["--ro-bind", group_path, "/etc/group"])
    seccomp_args: list[str] = []
    if seccomp_fd is not None:
        # bwrap reads the BPF program from this fd at exec time; the caller
        # keeps it open via Popen(pass_fds=[...]).
        seccomp_args = ["--seccomp", str(seccomp_fd)]
    cap_args: list[str] = []
    if capdrop_whitelist is not None and cap_drop_supported:
        # --cap-drop ALL then --cap-add per whitelist entry: bwrap(1)
        # processes the two in command-line order, so the adds survive.
        cap_args = bwrap_capability_args(capdrop_whitelist)
    argv = [
        bwrap_path,
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        *seccomp_args,
        *cap_args,
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
        *identity_binds,
        workspace_bind,
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

    # Pledge semantic layer: declare before anything runs. A Shell execution
    # inherently spawns and execs, so a pledge set without proc+exec is
    # refused here — fail closed, before the command exists.
    pledge_ctx: PledgeContext | None = None
    if request.pledges is not None:
        try:
            pledge_ctx = PledgeContext.pledge(request.pledges)
            pledge_ctx.require("proc")
            pledge_ctx.require("exec")
        except (PledgeError, PledgeViolation) as error:
            raise SandboxError(f"pledge refused: {error}") from error

    if chosen == "bwrap":
        assert caps.bwrap_path  # resolve_backend guaranteed usable
        seccomp_fd: int | None = None
        seccomp_file = None
        pass_fds: list[int] = []
        # The sandbox gets a synthetic identity: only the invoking user
        # exists inside (see _minimal_identity_files). The temp files live
        # under the workspace tmp dir, next to the seccomp program.
        tmpdir = workspace / ".northstar" / "tmp"
        tmpdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        passwd_content, group_content = _minimal_identity_files()
        identity_paths: list[str] = []
        try:
            for prefix, content in (("passwd-", passwd_content), ("group-", group_content)):
                fh = tempfile.NamedTemporaryFile(prefix=prefix, dir=str(tmpdir), delete=False)
                try:
                    fh.write(content.encode("utf-8"))
                    fh.flush()
                finally:
                    fh.close()
                identity_paths.append(fh.name)
        except Exception:
            for name in identity_paths:
                try:
                    os.unlink(name)
                except OSError:
                    pass
            raise
        passwd_path, group_path = identity_paths
        detail = "network namespace unshared; workspace is the only writable bind"
        if (request.landlock or "auto").strip().lower() != "off":
            # Landlock is a process-backend mechanism; bwrap already confines
            # paths more strongly via read-only mounts, so there is nothing
            # to add here. Stated, not silently assumed.
            detail += "; landlock n/a (bwrap mounts already confine paths)"
        if pledge_ctx is not None and not ({"wpath", "cpath"} & pledge_ctx.promises):
            detail = "network namespace unshared; workspace is read-only (pledge: no wpath/cpath)"
        if seccomp_mode != "off":
            # The BPF denylist rides into bwrap on an inherited fd
            # (``bwrap --seccomp FD``). A temp file under the workspace tmp dir
            # keeps the bytes off any shared location.
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
            wrapped = _bwrap_argv(
                request,
                bwrap_path=caps.bwrap_path,
                seccomp_fd=seccomp_fd,
                passwd_path=passwd_path,
                group_path=group_path,
                capdrop_whitelist=request.capdrop_whitelist,
                cap_drop_supported=caps.bwrap_cap_drop,
            )
            if request.capdrop_whitelist is not None:
                if caps.bwrap_cap_drop:
                    wl = ",".join(sorted(parse_whitelist(request.capdrop_whitelist))) or "deny-all"
                    detail += f"; capdrop: --cap-drop ALL (+{wl})"
                else:
                    detail += "; capdrop not applied: bwrap on this host has no --cap-drop"
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
                seccomp_file.close()
            unlink_names = identity_paths
            if seccomp_file is not None:
                unlink_names = [seccomp_file.name] + unlink_names
            for name in unlink_names:
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
    landlock_mode = (request.landlock or "auto").strip().lower()
    if landlock_mode == "on" and not (
        sys.platform.startswith("linux") and landlock_supported()
    ):
        # No silent downgrade either: the operator required the path
        # allowlist, and this host cannot enforce one.
        raise SandboxError(
            "landlock='on' requires a Linux kernel with Landlock "
            f"(this host: {sys.platform}, landlock_supported={landlock_supported()})."
        )
    base_detail = (
        "process backend: cwd pinned and env scrubbed, but the host filesystem "
        "and network are still reachable — install bubblewrap for OS isolation"
    )
    exec_argv: Sequence[str] = request.argv
    python = shutil.which("python3") or sys.executable
    if seccomp_mode != "off" and sys.platform.startswith("linux"):
        # The filter rides in on a python wrapper that prctl()s it before
        # exec (see tools/seccomp.py: no preexec_fn, so no fork-in-threads
        # hazard). The audit trail keeps the original argv; the wrapper is
        # an implementation detail named in `detail`.
        python = shutil.which("python3") or sys.executable
        if pledge_ctx is not None:
            # Pledge mechanism layer: Landlock self-restriction (filesystem
            # promises -> PATH_BENEATH rules) + the same seccomp denylist,
            # applied irreversibly before exec. Reported honestly in `detail`.
            tmpdir = str(workspace / ".northstar" / "tmp")
            rules = filesystem_rules(
                pledge_ctx.promises, workspace=str(workspace), tmpdir=tmpdir
            )
            exec_argv = pledge_loader_argv(rules, request.argv, python=python)
            report = enforcement_report(pledge_ctx.promises, backend="process")
            landlock_note = (
                "landlock self-restriction active"
                if report["landlock"]["available"]
                else f"landlock unavailable ({report['landlock']['detail']}); "
                "semantic pledge still fails closed"
            )
            detail = base_detail + f"; pledge {sorted(pledge_ctx.promises)}; {landlock_note}"
        else:
            exec_argv = prctl_loader_argv(request.argv, python=python)
            detail = base_detail + "; seccomp denylist active (prctl, EPERM on deny)"
    else:
        detail = base_detail + "; seccomp not applied"
        if seccomp_mode != "off":
            detail += f" ({sys.platform} cannot load a BPF filter)"
    # Capability drop: outermost wrapper, so the report fd is written and
    # closed before the next exec and the drop is the last gate the tool
    # command passes. Linux only; elsewhere the request is refused loudly
    # only when an explicit whitelist was asked for (validated above).
    capdrop_report: dict[str, Any] | None = None
    cap_pipe_r: int | None = None
    cap_pipe_w: int | None = None
    capdrop_pass_fds: list[int] = []
    if request.capdrop_whitelist is not None:
        if sys.platform.startswith("linux"):
            python = shutil.which("python3") or sys.executable
            cap_pipe_r, cap_pipe_w = os.pipe()
            exec_argv = capdrop_loader_argv(
                exec_argv,
                sorted(parse_whitelist(request.capdrop_whitelist)),
                fd=cap_pipe_w,
                python=python,
            )
            capdrop_pass_fds.append(cap_pipe_w)
            detail += "; capdrop launcher active (capset zeroing, fail-closed)"
        else:
            detail += "; capdrop not applied (non-Linux: no capset/prctl)"
    if landlock_mode != "off" and sys.platform.startswith("linux") and landlock_supported():
        # The Landlock allowlist rides in on an outer python wrapper (see
        # tools/sandbox.py): path layer outside, syscall layer inside.
        spec = default_profile(str(workspace))
        spec["mode"] = landlock_mode
        exec_argv = landlock_loader_argv(exec_argv, spec, python=python)
        detail += "; landlock path allowlist active (FS deny-by-default, TCP denied)"
    elif landlock_mode != "off":
        # Graceful degradation, stated out loud: the loader would also warn
        # on stderr, but the detail line is what the operator reads.
        detail += "; landlock not applied (kernel lacks Landlock; seccomp layer still enforced)"
    result = _run_popen(
        exec_argv,
        cwd=cwd,
        env=env,
        timeout_ms=request.timeout_ms,
        max_output_bytes=request.max_output_bytes,
        backend="process",
        isolation="process",
        detail=detail,
        pass_fds=capdrop_pass_fds,
    )
    if cap_pipe_r is not None:
        # The loader closes the write end before exec; the child is reaped
        # by now, so every write end is gone and the read terminates.
        assert cap_pipe_w is not None
        os.close(cap_pipe_w)
        try:
            with os.fdopen(cap_pipe_r, "r", encoding="utf-8") as handle:
                raw_report = handle.read(1 << 20)
        except OSError:
            raw_report = ""
            cap_pipe_r = None
        if raw_report.strip():
            try:
                parsed = json.loads(raw_report)
                capdrop_report = parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                capdrop_report = None
        # Append onto the detail _run_popen returned: it may carry
        # timeout/output-cap notes, which must not be clobbered.
        final_detail = result.detail
        if capdrop_report is not None:
            final_detail = final_detail + "; " + summarize_report(capdrop_report)
        else:
            final_detail = final_detail + "; capdrop report unreadable (child killed before reporting?)"
    else:
        final_detail = result.detail
    # The audit trail records what the caller asked for, not the wrapper.
    return replace(result, argv=request.argv, capdrop=capdrop_report, detail=final_detail)


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
