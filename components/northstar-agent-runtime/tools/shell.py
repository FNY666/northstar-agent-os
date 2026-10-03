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
import shutil
from typing import TYPE_CHECKING, Any

from tools.os_sandbox import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_MS,
    MAX_OUTPUT_BYTES,
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
    from tools import ToolResult

    if ctx.sandbox is None:
        return ToolResult.error("Shell requires a workspace sandbox")
    try:
        argv = parse_shell_argv(payload)
        timeout_ms = _coerce_timeout(payload.get("timeout_ms"), default=DEFAULT_TIMEOUT_MS)
        max_output = _coerce_max_output(payload.get("max_output_bytes"), default=DEFAULT_MAX_OUTPUT_BYTES)
        raw_cwd = payload.get("cwd", ".") or "."
        if not isinstance(raw_cwd, str):
            raise SandboxError("cwd must be a string")
        # must_exist so we don't create cwd via a write-shaped resolve; Shell is
        # not a mkdir tool.
        cwd_path = ctx.resolve(raw_cwd, must_exist=True)
        if not cwd_path.is_dir():
            raise SandboxError(f"cwd is not a directory: {raw_cwd}")
        backend = str(payload.get("backend") or ctx.service("shell_backend") or "auto")
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

        request = SandboxRequest(
            argv=argv,
            cwd=cwd_path,
            workspace=ctx.sandbox.root_real,
            timeout_ms=timeout_ms,
            max_output_bytes=max_output,
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
    if result.timed_out:
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
            "properties": {
                "argv": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Executable + arguments (preferred). No shell interpolation.",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command string; runs as sh -c inside the sandbox.",
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
                    "description": f"Stdout/stderr cap each (default {DEFAULT_MAX_OUTPUT_BYTES}).",
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Extra env vars (cannot override PATH/HOME/TMPDIR/LD_*).",
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


def sandbox_status_line(backend: str = "auto") -> str:
    """One-line summary for doctor / dry-run."""
    caps = probe_capabilities()
    try:
        from tools.os_sandbox import resolve_backend

        chosen = resolve_backend(backend, capabilities=caps)
    except SandboxError as error:
        return f"sandbox=unavailable ({error})"
    if chosen == "bwrap":
        return f"sandbox=bwrap (OS isolation) — {caps.bwrap_detail}"
    return (
        f"sandbox=process (cwd+env only; host FS reachable) — "
        f"bwrap: {caps.bwrap_detail}"
    )


__all__ = [
    "SHELL_KIND",
    "SHELL_NAME",
    "parse_shell_argv",
    "sandbox_status_line",
    "shell_handler",
    "shell_tool_spec",
]
