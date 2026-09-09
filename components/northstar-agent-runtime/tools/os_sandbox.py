"""OS-level execution backends for governed command tools (Shell).

Two backends, one contract:

* **bwrap** (preferred) — bubblewrap with a read-only host view, a writable
  bind of the workspace, no network namespace, and die-with-parent. This is the
  isolation level the threat model calls a *sandbox*.
* **process** (fallback) — a scrubbed subprocess with cwd pinned inside the
  workspace, resource limits, and process-group cleanup. This is *not* OS
  isolation: a determined command can still reach the rest of the host via
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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: Hard ceilings a single Shell invocation may not exceed. Operators may only
#: tighten these (via tool payload or run config), never widen past the runtime.
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 300_000
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_MAX_ARGV = 64
MAX_ARGV_BYTES = 32 * 1024
DEFAULT_MAX_ENV = 32

#: Where a sandboxed command may put scratch files, relative to the workspace. One name on
#: purpose: :func:`_scrubbed_env` creates it, the Shell tool re-binds it writable inside the
#: read-only governance tree, and the drift watch ignores it. Two spellings would drift.
SANDBOX_TMP_RELATIVE = ".northstar/tmp"

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
    #: Workspace paths the child must not be able to write even though the workspace is its
    #: only writable bind: the tree the run is gated by. Enforced by a read-only re-bind on
    #: bwrap, which is what lets the permission gate keep its promise across an approved
    #: ``Shell`` call (audit F4). On the process backend these are inert - nothing can be
    #: bound without user namespaces - and ``governance_watch`` detects there instead.
    read_only_paths: tuple[Path, ...] = ()
    #: Paths *inside* ``read_only_paths`` that stay writable on purpose: the documented
    #: carve-outs (workspace memory, the sandbox tmp dir). Applied after the read-only binds,
    #: because the later bind wins - which is also why a caller cannot widen a rule by
    #: listing a carve-out that was never protected.
    writable_paths: tuple[Path, ...] = ()


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
        "TMPDIR": str(workspace / SANDBOX_TMP_RELATIVE),
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
    for label, paths in (("read_only_paths", request.read_only_paths), ("writable_paths", request.writable_paths)):
        for path in paths:
            candidate = Path(workspace) / path if not Path(path).is_absolute() else Path(path)
            resolved = _contained_target(candidate, workspace=workspace)
            try:
                resolved.relative_to(workspace)
            except ValueError as error:
                raise SandboxError(f"{label} {path} escapes the workspace ({resolved})") from error


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
) -> SandboxResult:
    """Shared runner: process-group kill on timeout, capped pipes, no shell=True."""
    # Ensure TMPDIR exists for the child (workspace-scoped).
    tmp = Path(env.get("TMPDIR") or (cwd / SANDBOX_TMP_RELATIVE))
    try:
        tmp.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        pass

    started = time.monotonic()
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


#: Per-process verdicts for "did the read-only bind actually hold", keyed by
#: ``(workspace, protected paths)``. The answer depends on this kernel and this bwrap, not on
#: the command about to run, so a run that makes forty ``Shell`` calls pays one probe - and
#: every later call gets the same *answer* rather than the same silence.
_BIND_VERDICTS: dict[tuple, tuple[bool, str]] = {}
_BIND_VERDICTS_LOCK = threading.Lock()


def _assert_binds_hold(workspace: Path, read_only_paths: Sequence[Path], *, caps: SandboxCapabilities) -> None:
    """Refuse to run when a path this sandbox promised to protect is writable from inside it.

    ``resolve_backend`` already refuses to lie about *which* backend you get; this refuses the
    next lie down. ``--ro-bind-try`` is deliberately quiet when it cannot do the job, so a bind
    that did not hold would have let a run advertise "governance tree bound read-only" in its own
    audit while the tree was open. One probe per (workspace, set of paths) per process, and the
    verdict is cached whether it is good or bad - a host where the bind fails must fail every
    call the same way, not loudly once and silently afterwards.
    """
    key = (str(workspace), tuple(sorted(str(path) for path in read_only_paths)))
    with _BIND_VERDICTS_LOCK:
        verdict = _BIND_VERDICTS.get(key)
    if verdict is None:
        verdict = probe_governance_binds(workspace, read_only_paths, capabilities=caps, phase=True)
        with _BIND_VERDICTS_LOCK:
            _BIND_VERDICTS[key] = verdict
    if not verdict[0]:
        raise SandboxError(
            f"the governance bind this backend promised does not hold: {verdict[1]} - refusing "
            "to run a command that could rewrite the policy it is gated by (repair or install "
            "bubblewrap, or accept the weaker boundary with --sandbox process)"
        )


def reset_bind_verdicts() -> None:
    """Forget the cached verdicts. For tests and for a doctor run after installing bwrap."""
    with _BIND_VERDICTS_LOCK:
        _BIND_VERDICTS.clear()


def _flagged(flag: str, pairs: Mapping[str, str]) -> list[str]:
    """Flatten ``{src: dst}`` into bwrap's flat argument list."""
    out: list[str] = []
    for source, destination in pairs.items():
        out.extend([flag, source, destination])
    return out


def _contained_target(candidate: Path, *, workspace: Path) -> Path:
    """Realpath of ``candidate`` when it exists, normalised path when it does not.

    Two callers need the same thing - validation and bind construction - and they must agree:
    a path that validates as "inside the workspace" has to bind as the same path. A missing file
    cannot be realpath'ed (that would resolve through a symlink a later write may not create), so
    it is only normalised, and the ``--*-try`` flags make a vanished target a no-op at bind time.
    """
    if candidate.exists():
        return Path(os.path.realpath(str(candidate)))
    return Path(os.path.normpath(str(candidate)))


def _bind_pairs(paths: Iterable[Path], *, workspace: Path) -> dict[str, str]:
    """Ordered, de-duplicated ``source -> destination`` map for a set of bind requests."""
    seen: dict[str, str] = {}
    for raw in paths:
        candidate = Path(workspace) / raw if not Path(raw).is_absolute() else Path(raw)
        resolved = _contained_target(candidate, workspace=workspace)
        try:
            resolved.relative_to(workspace)
        except ValueError:
            continue  # outside the workspace: refused by validation, never bound
        seen[str(resolved)] = str(resolved)
    return dict(sorted(seen.items()))


def ensure_governance_dirs(workspace: Path, paths: Iterable[Path]) -> list[Path]:
    """Create a missing governance *directory* so a read-only bind has something to bind.

    The hole being closed is the shape CVE-2026-25725 was: "not protected at startup" and
    "did not exist at startup" are the same door. Only a dot-directory that is a direct child
    of the workspace is created - an empty ``.git`` would confuse real tooling instead of
    protecting anything, and a deeper path is the caller business to create.
    """
    created: list[Path] = []
    for raw in paths:
        candidate = Path(workspace) / raw if not Path(raw).is_absolute() else Path(raw)
        if candidate.exists():
            continue
        if candidate.parent != Path(workspace) or not candidate.name.startswith("."):
            continue
        try:
            candidate.mkdir(mode=0o700, parents=False, exist_ok=True)
        except OSError:
            continue
        created.append(candidate)
    return created


def _bwrap_argv(request: SandboxRequest, *, bwrap_path: str) -> list[str]:
    """Build a conservative bubblewrap command line around the user argv."""
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    # Host paths the child needs to actually execute anything useful. Bound
    # read-only; the workspace is the only writable bind.
    ro_binds = []
    for host_path in ("/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc/resolv.conf", "/etc/ssl", "/etc/passwd", "/etc/group"):
        if Path(host_path).exists():
            ro_binds.extend(["--ro-bind", host_path, host_path])
    argv = [
        bwrap_path,
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
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
        # Later binds win in bwrap, so the governance tree is re-bound read-only *after* the
        # workspace, and the carve-outs after that. Without this block the run's own policy
        # file is writable by the very command the run approved.
        *_flagged("--ro-bind-try", _bind_pairs(request.read_only_paths, workspace=workspace)),
        *_flagged("--bind-try", _bind_pairs(request.writable_paths, workspace=workspace)),
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
    phase: bool = False,
) -> SandboxResult:
    """Run ``request`` under the resolved backend. Never uses ``shell=True``.

    ``phase=True`` skips the bind-holds probe and is reserved for the probe itself.
    """
    _validate_request(request)
    caps = capabilities or probe_capabilities()
    chosen = resolve_backend(backend, capabilities=caps)
    workspace = Path(os.path.realpath(str(request.workspace)))
    cwd = Path(os.path.realpath(str(request.cwd)))
    env = _scrubbed_env(request.env, workspace=workspace)

    if chosen == "bwrap":
        assert caps.bwrap_path  # resolve_backend guaranteed usable
        # A protected tree that does not exist yet is a hole, not a relief: create it so the
        # read-only bind has a target, otherwise "nothing to protect" means "free to create".
        ensure_governance_dirs(workspace, request.read_only_paths)
        if request.read_only_paths and not phase:
            _assert_binds_hold(workspace, request.read_only_paths, caps=caps)
        wrapped = _bwrap_argv(request, bwrap_path=caps.bwrap_path)
        return _run_popen(
            wrapped,
            cwd=cwd,  # bwrap --chdir is authoritative; cwd here is best-effort
            env=env,
            timeout_ms=request.timeout_ms,
            max_output_bytes=request.max_output_bytes,
            backend="bwrap",
            isolation="os",
            detail=(
                "network namespace unshared; workspace is the only writable bind"
                + (
                    f"; {len(request.read_only_paths)} governance path(s) bound read-only"
                    if request.read_only_paths
                    else "; no governance bind requested (policy files are NOT write-blocked here)"
                )
            ),
        )

    return _run_popen(
        request.argv,
        cwd=cwd,
        env=env,
        timeout_ms=request.timeout_ms,
        max_output_bytes=request.max_output_bytes,
        backend="process",
        isolation="process",
        detail=(
            "process backend: cwd pinned and env scrubbed, but the host filesystem "
            "and network are still reachable — install bubblewrap for OS isolation"
        ),
    )




def probe_governance_binds(
    workspace: str | os.PathLike[str],
    read_only_paths: Sequence[Path],
    *,
    capabilities: SandboxCapabilities | None = None,
) -> tuple[bool, str]:
    """Ask a real sandbox whether it can still write where the gate says it may not.

    One throwaway command inside a sandbox built exactly like a Shell call would be, so the
    answer is about this host and this kernel rather than about a manual. ``(True, ...)`` only
    when every protected path refused the write; ``(False, why)`` when a bind did not hold or
    bwrap cannot run at all - the caller reports "not verifiable here" as its own state, never
    as a pass.

    ``phase`` exists only so :func:`_assert_binds_hold` can call this without recursing into
    itself; every other caller leaves it out. One honest limit: the probe writes a single file
    inside each protected directory and looks for it afterwards. A filesystem that permits the
    write but hides it (an overlay oddity) would read as "held" - strictly better than not
    looking, and the reason the answer is a verdict about this host rather than a promise about
    the tool.
    """
    root = Path(os.path.realpath(str(workspace)))
    caps = capabilities or probe_capabilities()
    if not caps.bwrap_usable or not caps.bwrap_path:
        return False, "not verifiable on this host: " + caps.bwrap_detail
    targets = [Path(str(path)) for path in read_only_paths if str(path).strip()]
    if not targets:
        return True, "nothing protected, nothing to probe"
    probe_name = ".northstar-drift-probe"
    checks: list[str] = []
    for target in targets:
        candidate = root / target if not target.is_absolute() else target
        # Deliberately not created here: this function runs inside `northstar doctor`, whose
        # contract is "no file writes". A missing target is reported as skipped - run_sandboxed
        # is where a missing governance directory is created so the bind has a target.
        if not candidate.is_dir():
            checks.append(f"{target}: absent, nothing to bind (created by a real run, not by this probe)")
            continue
        probe = candidate / probe_name
        request = SandboxRequest(
            argv=("/bin/sh", "-c", "touch " + probe.as_posix()),
            cwd=root,
            workspace=root,
            read_only_paths=tuple(targets),
        )
        result = run_sandboxed(request, backend="bwrap", capabilities=caps, phase=phase)
        wrote = probe.exists()
        try:
            probe.unlink(missing_ok=True)
        except OSError:
            pass
        if wrote:
            return False, f"{target} is writable inside the sandbox: the read-only bind did not hold"
        checks.append(f"{target}: refused (exit={result.exit_code})")
    return True, "; ".join(checks)

__all__ = [
    "BACKENDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_MS",
    "MAX_OUTPUT_BYTES",
    "MAX_TIMEOUT_MS",
    "SandboxCapabilities",
    "SandboxError",
    "SandboxRequest",
    "SANDBOX_TMP_RELATIVE",
    "SandboxResult",
    "ensure_governance_dirs",
    "probe_capabilities",
    "probe_governance_binds",
    "reset_bind_verdicts",
    "reset_capabilities_cache",
    "resolve_backend",
    "run_sandboxed",
]
