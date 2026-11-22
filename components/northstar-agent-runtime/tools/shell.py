"""Shell tool: governed command execution inside the OS sandbox.

Design rules (spine §1 — next-gen Agent OS):

1. **No host Full Auto.** ``Shell`` is kind ``exec`` (mutating). Under the
   default permission mode it is denied until an operator passes
   ``--allow-tool Shell`` (or an explicit approval callback). ``acceptEdits``
   does **not** cover it — that mode is for file edits, not command execution.
2. **No ``shell=True``.** The payload is either an ``argv`` list (preferred) or a
   ``command`` string that becomes ``["/bin/sh", "-c", command]`` *inside* the
   sandbox. Metacharacters in ``command`` are intentional and still confined by
   the backend; they are never interpreted by Python's shell.
3. **cwd must stay in the workspace.** Resolved through :class:`ToolSandbox`
   before the OS backend sees it.
4. **Honest isolation.** The tool result names the backend (``bwrap`` / ``process``)
   and the isolation level. A process-backend run that looks "sandboxed" in the
   transcript would be a lie; we refuse to tell it.
5. **Caps.** Timeout, output bytes, and argv size are closed ceilings. Payload
   values may only tighten them.

Registration lives in :func:`tools.build_default_registry`; this module only
supplies the handler and schema so the registry stays a thin list.
"""
from __future__ import annotations

import os
import hashlib
import shlex
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.os_sandbox import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_MS,
    MAX_CPU_SECONDS,
    MAX_FILE_SIZE_BYTES,
    MAX_MEMORY_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_TASKS,
    MAX_TIMEOUT_MS,
    SandboxError,
    SandboxRequest,
    probe_capabilities,
    run_sandboxed,
)
from tools.capdrop import CapDropError
from tools.capdrop import resolve_capdrop as resolve_capdrop_policy
from tools.sandbox import LandlockError
from tools.sandbox import resolve_mode as resolve_landlock_mode
from tools.seccomp import SeccompError
from tools.seccomp import resolve_mode as resolve_seccomp_mode
from tools.pledge import PledgeError
from tools.pledge import resolve_pledges as resolve_pledge_set

if TYPE_CHECKING:
    from tools import ToolContext

# Avoid circular import of ToolSpec construction helpers — schema is plain dicts.
SHELL_NAME = "Shell"
SHELL_KIND = "exec"

_SH_CANDIDATES = ("/bin/sh", "/usr/bin/sh")

# Session memory: (run session_id, session name) -> {"cwd": str, "env": dict}.
# Keyed by ctx.session_id so sessions die with the run — no cross-run leakage.
# A session only remembers the workspace-relative cwd and extra env vars the
# agent already had the right to pass per-call; it grants no new privilege.
# cwd is re-resolved through ctx.resolve() on every call, so a deleted
# directory fails honestly instead of trusting stale state.
_session_state: dict[tuple[str, str], dict[str, Any]] = {}
_SESSION_NAME_MAX = 64


def _resolve_sh() -> str:
    for candidate in _SH_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("sh")
    if found:
        return found
    raise SandboxError("no /bin/sh available to run a command string")


def _coerce_timeout(value: Any, *, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise SandboxError(f"timeout_ms must be an integer, got {value!r}") from error
    if number < 1:
        raise SandboxError("timeout_ms must be >= 1")
    return min(number, MAX_TIMEOUT_MS)


def _coerce_max_output(value: Any, *, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise SandboxError(f"max_output_bytes must be an integer, got {value!r}") from error
    if number < 1:
        raise SandboxError("max_output_bytes must be >= 1")
    return min(number, MAX_OUTPUT_BYTES)


def _coerce_positive_limit(value: Any, *, name: str, default: int, maximum: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise SandboxError(f"{name} must be a positive integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise SandboxError(f"{name} must be a positive integer, got {value!r}") from error
    if number < 1:
        raise SandboxError(f"{name} must be >= 1")
    return min(number, maximum)


def parse_shell_argv(payload: dict[str, Any]) -> tuple[str, ...]:
    """Build the argv the sandbox will exec. Prefer ``argv``; ``command`` is sh -c."""
    if "argv" in payload and payload.get("argv") is not None:
        raw = payload.get("argv")
        if not isinstance(raw, (list, tuple)) or not raw:
            raise SandboxError("argv must be a non-empty list of strings")
        argv = []
        for item in raw:
            if not isinstance(item, str) or not item:
                raise SandboxError("argv entries must be non-empty strings")
            argv.append(item)
        if "command" in payload and payload.get("command") not in (None, ""):
            raise SandboxError("pass argv or command, not both")
        return tuple(argv)

    command = payload.get("command", payload.get("cmd"))
    if not isinstance(command, str) or not command.strip():
        raise SandboxError("Shell needs argv (list) or command (string)")
    # Explicit sh -c inside the sandbox — never Python shell=True.
    return (_resolve_sh(), "-c", command)


def shell_handler(payload: dict[str, Any], ctx: "ToolContext") -> Any:
    """Run one governed command in the configured OS sandbox backend."""
    # Local import: tools/__init__ registers this handler, so a top-level import
    # of ToolResult from tools would be a cycle.
    from tools import ToolAccessError, ToolResult

    if ctx.sandbox is None:
        return ToolResult.error("Shell requires a workspace sandbox")
    try:
        ctx.sandbox.require_shell_memory_access()
    except ToolAccessError as error:
        return ToolResult.error(f"Shell refused by workspace memory audience policy: {error}")
    try:
        argv = parse_shell_argv(payload)
        timeout_ms = _coerce_timeout(payload.get("timeout_ms"), default=DEFAULT_TIMEOUT_MS)
        max_output = _coerce_max_output(payload.get("max_output_bytes"), default=DEFAULT_MAX_OUTPUT_BYTES)
        cpu_limit_seconds = _coerce_positive_limit(
            payload.get("cpu_limit_seconds"),
            name="cpu_limit_seconds",
            default=min(MAX_CPU_SECONDS, max(1, (timeout_ms + 999) // 1000)),
            maximum=MAX_CPU_SECONDS,
        )
        memory_limit_mb = _coerce_positive_limit(
            payload.get("memory_limit_mb"),
            name="memory_limit_mb",
            default=DEFAULT_MAX_MEMORY_BYTES // (1024 * 1024),
            maximum=MAX_MEMORY_BYTES // (1024 * 1024),
        )
        file_size_limit_mb = _coerce_positive_limit(
            payload.get("file_size_limit_mb"),
            name="file_size_limit_mb",
            default=DEFAULT_MAX_FILE_SIZE_BYTES // (1024 * 1024),
            maximum=MAX_FILE_SIZE_BYTES // (1024 * 1024),
        )
        aggregate_resource_scope = str(ctx.service("shell_aggregate_resource_scope") or "off")
        if "max_tasks" in payload and aggregate_resource_scope == "off":
            raise SandboxError("max_tasks requires operator-enabled --shell-aggregate-resource-scope systemd")
        max_tasks = _coerce_positive_limit(
            payload.get("max_tasks"),
            name="max_tasks",
            default=MAX_TASKS,
            maximum=MAX_TASKS,
        )
        raw_cwd = payload.get("cwd", ".") or "."
        if not isinstance(raw_cwd, str):
            raise SandboxError("cwd must be a string")
        # Session memory: a named session remembers the last cwd and env so a
        # multi-step programming flow (cd, export, build, test) doesn't have
        # to re-establish context on every call. Explicit per-call cwd/env
        # win and update the session. Keyed by the run's session_id — sessions
        # never cross runs.
        session_name = payload.get("session")
        session_key: tuple[str, str] | None = None
        session_mem: dict[str, Any] | None = None
        if session_name is not None:
            if not isinstance(session_name, str) or not session_name.strip():
                raise SandboxError("session must be a non-empty string")
            if len(session_name) > _SESSION_NAME_MAX:
                raise SandboxError(f"session name too long (max {_SESSION_NAME_MAX})")
            session_key = (ctx.session_id, session_name)
            session_mem = _session_state.get(session_key)
            if session_mem is None:
                session_mem = {"cwd": ".", "env": {}}
            if "cwd" not in payload:
                raw_cwd = session_mem["cwd"]
        # must_exist so we don't create cwd via a write-shaped resolve; Shell is
        # not a mkdir tool.
        cwd_path = ctx.resolve(raw_cwd, must_exist=True)
        if not cwd_path.is_dir():
            raise SandboxError(f"cwd is not a directory: {raw_cwd}")
        # A skill script is reviewed at setup, then executed only through this
        # governed Shell path. Re-check direct argv references immediately before
        # spawn so post-setup edits cannot silently replace reviewed script bytes.
        pins = ctx.service("skill_digests") or {}
        if pins:
            candidates = list(argv)
            if len(argv) >= 3 and argv[1] == "-c":
                try:
                    candidates.extend(shlex.split(argv[2]))
                except ValueError:
                    pass  # the shell itself will report the malformed command
            for token in candidates:
                if not isinstance(token, str) or not token or token.startswith("-"):
                    continue
                candidate = Path(token)
                if not candidate.is_absolute():
                    candidate = cwd_path / candidate
                candidate = Path(os.path.normpath(str(candidate)))
                try:
                    relative = candidate.relative_to(ctx.sandbox.root_real).as_posix()
                except ValueError:
                    continue
                expected = pins.get(relative)
                if expected is None:
                    continue
                try:
                    from skills import MAX_SKILL_FILE_BYTES, _read_bounded_regular

                    pinned_bytes = _read_bounded_regular(candidate, MAX_SKILL_FILE_BYTES)
                except OSError as error:
                    return ToolResult.error(f"cannot verify pinned skill script: {error}", skill_integrity="failed")
                if len(pinned_bytes) > MAX_SKILL_FILE_BYTES:
                    return ToolResult.error("pinned skill script exceeds its byte limit", skill_integrity="failed")
                actual = hashlib.sha256(pinned_bytes).hexdigest()
                if actual != expected:
                    return ToolResult.error(
                        "skill script changed after run setup; refusing unreviewed code",
                        skill_integrity="failed",
                    )
        if session_mem is not None and session_key is not None:
            # Remember the cwd that actually resolved (re-resolved every call,
            # so a deleted directory fails here instead of going stale).
            session_mem["cwd"] = raw_cwd
            _session_state[session_key] = session_mem
        # Backend choice is host policy: the model may tighten per-call
        # controls below, but must not replace a host-selected bwrap backend
        # with the weaker process backend.
        backend = str(ctx.service("shell_backend") or "auto")
        # Seccomp is tighten-only: a per-call payload may move toward "on" but
        # never loosen what the operator configured via --seccomp.
        try:
            seccomp = resolve_seccomp_mode(
                payload.get("seccomp"), ctx.service("shell_seccomp")
            )
        except SeccompError as error:
            return ToolResult.error(str(error))
        # Capability drop is tighten-only like seccomp: a per-call payload may
        # narrow the operator's whitelist but never widen it or switch the
        # launcher off (see tools.capdrop.resolve_capdrop).
        try:
            capdrop_whitelist = resolve_capdrop_policy(
                payload.get("capdrop"), ctx.service("shell_capdrop")
            )
        except CapDropError as error:
            return ToolResult.error(str(error))
        # Landlock is tighten-only, same as seccomp: a per-call payload may
        # move toward "on" but never loosen the operator's --landlock.
        try:
            landlock = resolve_landlock_mode(
                payload.get("landlock"), ctx.service("shell_landlock")
            )
        except LandlockError as error:
            return ToolResult.error(str(error))
        # Pledge is tighten-only like seccomp: a per-call payload may move
        # toward a subset of the operator's shell_pledges, never widen it.
        try:
            raw_pledges = payload.get("pledges")
            pledges = resolve_pledge_set(
                list(raw_pledges) if raw_pledges is not None else None,
                ctx.service("shell_pledges"),
            )
        except PledgeError as error:
            return ToolResult.error(str(error))
        env_payload = payload.get("env")
        env = None
        if env_payload is not None:
            if not isinstance(env_payload, dict):
                raise SandboxError("env must be an object of string keys to string values")
            env = {str(k): str(v) for k, v in env_payload.items()}
        if session_mem is not None and session_key is not None:
            # Session env persists across calls; per-call env wins on conflict.
            # The sandbox still filters protected vars (PATH/HOME/TMPDIR/LD_*)
            # downstream, so remembered env grants nothing new.
            merged = dict(session_mem["env"])
            if env:
                merged.update(env)
            env = merged or None
            session_mem["env"] = dict(merged)
            _session_state[session_key] = session_mem

        request = SandboxRequest(
            argv=argv,
            cwd=cwd_path,
            workspace=ctx.sandbox.root_real,
            timeout_ms=timeout_ms,
            max_output_bytes=max_output,
            cpu_limit_seconds=cpu_limit_seconds,
            memory_limit_bytes=memory_limit_mb * 1024 * 1024,
            file_size_limit_bytes=file_size_limit_mb * 1024 * 1024,
            aggregate_resource_scope=aggregate_resource_scope,
            max_tasks=max_tasks,
            env=env,
            network=bool(payload.get("network", False)),
            seccomp=seccomp,
            capdrop_whitelist=capdrop_whitelist,
            landlock=landlock,
            pledges=pledges,
        )
        result = run_sandboxed(request, backend=backend)
    except SandboxError as error:
        return ToolResult.error(str(error))
    except Exception as error:  # noqa: BLE001 - tool errors must not kill the run
        return ToolResult.error(f"Shell failed: {type(error).__name__}: {error}")

    body = result.render()
    data = result.as_dict()
    data["cwd"] = ctx.relative(cwd_path)
    data["pledges"] = list(pledges)
    # A non-zero exit is a tool *result*, not a tool *crash*: the model must see
    # stdout/stderr to decide what to do next. timed_out is the only case we
    # mark is_error so the loop's PostToolUseFailure hooks can fire.
    if result.timed_out or result.aggregate_setup_failed or result.aggregate_cleanup_failed:
        return ToolResult(content=body, is_error=True, truncated=result.truncated, data=data)
    return ToolResult(content=body, is_error=False, truncated=result.truncated, data=data)


def shell_tool_spec():
    """Build the :class:`ToolSpec` for Shell (lazy import to keep tools package light)."""
    from tools import ToolSpec

    return ToolSpec(
        name=SHELL_NAME,
        description=(
            "Run a command inside the Northstar OS sandbox. Prefer argv as a JSON list of "
            "strings (no shell metacharacters). A string `command` is executed as "
            "`sh -c` *inside* the sandbox. Denied by default under permission mode "
            "`default` — pass --allow-tool Shell. Isolation is bwrap when available, "
            "otherwise a scrubbed process (cwd pinned; host FS still reachable — see "
            "docs/concepts/threat-model.md). No network namespace sharing."
        ),
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "anyOf": [
                {"required": ["argv"]},
                {"required": ["command"]},
                {"required": ["cmd"]},
            ],
            "properties": {
                "argv": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                    "description": "Executable + arguments (preferred). No shell interpolation.",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command string; runs as sh -c inside the sandbox.",
                },
                "cmd": {
                    "type": "string",
                    "description": "Compatibility alias for command; runs as sh -c inside the sandbox.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory relative to the workspace (default: .).",
                },
                "timeout_ms": {
                    "type": "integer",
                    "minimum": 1,
                    "description": f"Deadline in ms (default {DEFAULT_TIMEOUT_MS}, max {MAX_TIMEOUT_MS}).",
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "description": f"Combined stdout+stderr cap (default {DEFAULT_MAX_OUTPUT_BYTES}).",
                },
                "cpu_limit_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_CPU_SECONDS,
                    "description": "Per-process CPU seconds (default follows timeout; hard runtime ceiling applies).",
                },
                "memory_limit_mb": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_MEMORY_BYTES // (1024 * 1024),
                    "description": "Per-process address-space limit in MiB (default and maximum 2048; not a process-tree total).",
                },
                "file_size_limit_mb": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_FILE_SIZE_BYTES // (1024 * 1024),
                    "description": "Maximum individual file size in MiB (default and maximum 1024; not a workspace quota).",
                },
                "seccomp": {
                    "type": "string",
                    "enum": ["auto", "on", "off"],
                    "description": "Tighten-only per-call syscall filter mode; cannot weaken the host setting.",
                },
                "landlock": {
                    "type": "string",
                    "enum": ["auto", "on", "off"],
                    "description": "Tighten-only per-call filesystem policy; cannot weaken the host setting.",
                },
                "max_tasks": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TASKS,
                    "description": (
                        "Maximum aggregate processes/threads in the Shell cgroup (default 128); "
                        "effective only when the operator enables the systemd resource scope."
                    ),
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Extra env vars (cannot override PATH/HOME/TMPDIR/LD_*).",
                },
                "session": {
                    "type": "string",
                    "description": (
                        "Named session: remembers cwd and env across calls so a "
                        "multi-step flow (cd, export, build, test) keeps context. "
                        "Explicit per-call cwd/env win and update the session. "
                        "Sessions are scoped to the current run and never cross runs."
                    ),
                },
                "capdrop": {
                    "description": (
                        "Linux capability whitelist for the child (list of CAP_* "
                        "names, or a comma-separated string). Default deny-all. "
                        "Tighten-only: a call may only narrow the operator's "
                        "--capdrop whitelist, never widen it or switch the "
                        "launcher off."
                    ),
                },
                "pledges": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Pledge-style promise set (pledge(2) semantics: declare, "
                        "tighten-only, never widen). May only be a subset of the "
                        "operator's shell_pledges. Operations outside the set "
                        "fail closed. Promises: stdio rpath wpath cpath tmppath "
                        "dpath unix inet dns proc exec id clock tty."
                    ),
                },
            },
        },
        handler=shell_handler,
        kind=SHELL_KIND,  # type: ignore[arg-type]
        is_mutating=True,
        needs_workspace=True,
    )


def sandbox_status_line(backend: str = "auto", aggregate_resource_scope: str = "off") -> str:
    """One-line summary for doctor / dry-run."""
    caps = probe_capabilities()
    try:
        from tools.os_sandbox import resolve_backend

        chosen = resolve_backend(backend, capabilities=caps)
    except SandboxError as error:
        return f"sandbox=unavailable ({error})"
    aggregate_note = (
        "; aggregate cgroup v2 MemoryMax/TasksMax/CPUQuota required via systemd system scope"
        if aggregate_resource_scope == "systemd"
        else ""
    )
    if chosen == "bwrap":
        return f"sandbox=bwrap (OS isolation{aggregate_note}) — {caps.bwrap_detail}"
    return (
        f"sandbox=process (host FS reachable; Linux seccomp blocks socket creation when active) — "
        f"bwrap: {caps.bwrap_detail}; per-process CPU/memory/file-size ceilings only, "
        + ("aggregate cgroup v2 quota required" if aggregate_resource_scope == "systemd" else "no runtime-managed aggregate cgroup quota")
    )


__all__ = [
    "SHELL_KIND",
    "SHELL_NAME",
    "parse_shell_argv",
    "sandbox_status_line",
    "shell_handler",
    "shell_tool_spec",
]
