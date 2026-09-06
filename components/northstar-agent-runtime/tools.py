"""Sandboxed built-in tools.

Two invariants worth keeping:

- **One handler signature everywhere: ``handler(payload: dict, ctx: ToolContext) -> ToolResult``.**
  No handler takes ``(ctx, payload)`` or anything else; dispatch and hooks
  rely on the uniform shape.
- **Path containment is checked after symlink resolution.** Every tool path
  is resolved (following symlinks) before the containment test, so a symlink
  inside the workspace that points outside is denied, and a symlink that
  points back inside is fine.

Hard output limits: reads are capped at 256 KiB (truncated with a note),
grep is capped at 200 matches, listings at 500 entries.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

READ_LIMIT_BYTES = 256 * 1024
GREP_LIMIT = 200
LIST_LIMIT = 500

TOOL_KINDS = ("read", "edit", "exec", "delegate")

SIDECAR_MIN_TIMEOUT_MS = 1_000  # matches northstar-codex-sidecar
SIDECAR_MAX_TIMEOUT_MS = 300_000
SIDECAR_MAX_PROMPT_CHARS = 100_000


@dataclass(frozen=True)
class ToolResult:
    output: str
    is_error: bool = False
    meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ToolContext:
    """Everything a tool handler may need; handlers must not reach past it."""

    workspace: Path  # resolved absolute sandbox root
    session_id: str = ""
    depth: int = 0
    model: str = ""
    subagents: Optional[Mapping[str, Any]] = None  # AgentRegistry
    sidecar: Any = None  # SidecarClient or None
    # (agent_name: str, prompt: str) -> ToolResult; set by the agent loop.
    spawn_subagent: Optional[Callable[[str, str], ToolResult]] = None


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    kind: str  # one of TOOL_KINDS
    input_schema: Mapping[str, Any]
    handler: Callable[[dict[str, Any], ToolContext], ToolResult]


class ToolRegistry:
    def __init__(self, tools: list[Tool]):
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            if tool.name in self._tools:
                raise ValueError(f"duplicate tool: {tool.name}")
            self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def kinds(self) -> dict[str, str]:
        return {name: tool.kind for name, tool in self._tools.items()}

    def schemas(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": dict(t.input_schema)}
            for t in self._tools.values()
        ]

    def __iter__(self):
        return iter(self._tools.values())

    def __contains__(self, name: object) -> bool:
        return name in self._tools


def resolve_within_workspace(workspace: Path, raw: Any) -> Path | None:
    """Resolve ``raw`` (following symlinks) and check containment.

    Returns the resolved absolute path when it is inside ``workspace``
    (or is the root itself), else ``None``. ``workspace`` must already be
    resolved by the caller.
    """
    if not isinstance(raw, str) or not raw:
        return None
    base = Path(raw) if Path(raw).is_absolute() else workspace / raw
    try:
        resolved = base.resolve()
    except OSError:
        return None
    if resolved == workspace or workspace in resolved.parents:
        return resolved
    return None


def _rel(workspace: Path, target: Path) -> str:
    try:
        return str(target.relative_to(workspace))
    except ValueError:
        return str(target)


# --- handlers: uniform (payload, ctx) ----------------------------------------


def handle_read(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    raw = payload.get("path")
    target = resolve_within_workspace(ctx.workspace, raw)
    if target is None:
        return ToolResult(f"permission denied: path escapes workspace: {raw!r}", is_error=True)
    if not target.exists():
        return ToolResult(f"no such file: {_rel(ctx.workspace, target)}", is_error=True)
    if target.is_dir():
        return ToolResult(f"path is a directory: {_rel(ctx.workspace, target)}", is_error=True)
    size = target.stat().st_size
    with target.open("rb") as fh:
        data = fh.read(READ_LIMIT_BYTES)
    text = data.decode("utf-8", errors="replace")
    if size > READ_LIMIT_BYTES:
        text += f"\n[truncated: first {READ_LIMIT_BYTES // 1024} KiB of {size} bytes]"
    return ToolResult(text)


def handle_grep(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    pattern = payload.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return ToolResult("grep requires a non-empty 'pattern' string", is_error=True)
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return ToolResult(f"invalid pattern: {exc}", is_error=True)
    requested = payload.get("max_matches", GREP_LIMIT)
    try:
        max_matches = int(requested)
    except (TypeError, ValueError):
        return ToolResult("max_matches must be an integer", is_error=True)
    max_matches = max(1, min(max_matches, GREP_LIMIT))

    start = payload.get("path") or "."
    root = resolve_within_workspace(ctx.workspace, start)
    if root is None:
        return ToolResult(f"permission denied: path escapes workspace: {start!r}", is_error=True)
    if not root.is_dir():
        root = ctx.workspace

    matches: list[str] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if not (resolved == ctx.workspace or ctx.workspace in resolved.parents):
                continue  # symlinked file escaping the workspace
            try:
                text = resolved.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # skip binary files
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    matches.append(f"{_rel(ctx.workspace, resolved)}:{lineno}: {line.strip()}")
                    if len(matches) >= max_matches:
                        truncated = True
                        break
            if truncated:
                break
        if truncated:
            break
    if not matches:
        return ToolResult("no matches")
    output = "\n".join(matches)
    if truncated:
        output += f"\n[stopped at {max_matches} matches]"
    return ToolResult(output)


def handle_list(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    start = payload.get("path") or "."
    root = resolve_within_workspace(ctx.workspace, start)
    if root is None:
        return ToolResult(f"permission denied: path escapes workspace: {start!r}", is_error=True)
    if not root.is_dir():
        return ToolResult(f"not a directory: {_rel(ctx.workspace, root)}", is_error=True)

    entries: list[str] = []
    truncated = False
    base = root
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        current = Path(dirpath)
        for name in sorted(dirnames + filenames):
            child = current / name
            try:
                if child.is_symlink() and child.is_dir():
                    continue  # don't traverse symlinked directories
            except OSError:
                pass
            rel = child.relative_to(ctx.workspace)
            entries.append(str(rel) + ("/" if child.is_dir() else ""))
            if len(entries) >= LIST_LIMIT:
                truncated = True
                break
        if truncated:
            break
    if not entries:
        return ToolResult("(empty)")
    output = "\n".join(entries)
    if truncated:
        output += f"\n[stopped at {LIST_LIMIT} entries]"
    return ToolResult(output)


def handle_write(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    raw = payload.get("path")
    content = payload.get("content")
    if not isinstance(content, str):
        return ToolResult("write requires a 'content' string", is_error=True)
    target = resolve_within_workspace(ctx.workspace, raw)
    if target is None:
        return ToolResult(f"permission denied: path escapes workspace: {raw!r}", is_error=True)
    if target.exists() and target.is_dir():
        return ToolResult(f"path is a directory: {_rel(ctx.workspace, target)}", is_error=True)
    target.parent.mkdir(parents=True, exist_ok=True)  # parent is inside the sandbox
    target.write_text(content, encoding="utf-8")
    return ToolResult(f"wrote {len(content.encode('utf-8'))} bytes to {_rel(ctx.workspace, target)}")


def handle_edit(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    raw = payload.get("path")
    old = payload.get("old_string")
    new = payload.get("new_string")
    if not isinstance(old, str) or not old or not isinstance(new, str):
        return ToolResult("edit requires 'old_string' and 'new_string' strings", is_error=True)
    target = resolve_within_workspace(ctx.workspace, raw)
    if target is None:
        return ToolResult(f"permission denied: path escapes workspace: {raw!r}", is_error=True)
    if not target.is_file():
        return ToolResult(f"no such file: {_rel(ctx.workspace, target)}", is_error=True)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        return ToolResult("edit failed: old_string not found", is_error=True)
    if count > 1:
        return ToolResult(f"edit failed: old_string occurs {count} times; it must be unique", is_error=True)
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    return ToolResult(f"edited {_rel(ctx.workspace, target)}")


def handle_task(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    agent = payload.get("agent")
    prompt = payload.get("prompt")
    if not isinstance(agent, str) or not agent.strip():
        return ToolResult("task requires a non-empty 'agent' string", is_error=True)
    if not isinstance(prompt, str) or not prompt.strip():
        return ToolResult("task requires a non-empty 'prompt' string", is_error=True)
    if ctx.spawn_subagent is None:
        return ToolResult("no subagents are configured", is_error=True)
    return ctx.spawn_subagent(agent, prompt)


def handle_codex(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    if ctx.sidecar is None:
        return ToolResult("CodexReadOnly is not available: no sidecar socket configured", is_error=True)
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return ToolResult("CodexReadOnly requires a non-empty 'prompt' string", is_error=True)
    if len(prompt) > SIDECAR_MAX_PROMPT_CHARS:
        return ToolResult(
            f"CodexReadOnly prompt exceeds the sidecar limit of {SIDECAR_MAX_PROMPT_CHARS} characters",
            is_error=True,
        )
    timeout_ms = payload.get("timeout_ms", SIDECAR_MAX_TIMEOUT_MS)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
        return ToolResult("timeout_ms must be an integer", is_error=True)
    if not SIDECAR_MIN_TIMEOUT_MS <= timeout_ms <= SIDECAR_MAX_TIMEOUT_MS:
        return ToolResult(
            f"timeout_ms must be between {SIDECAR_MIN_TIMEOUT_MS} and {SIDECAR_MAX_TIMEOUT_MS}", is_error=True
        )
    result = ctx.sidecar.execute(prompt, timeout_ms)
    status = result.get("status")
    if status == "ok":
        return ToolResult(str(result.get("text", "")))
    detail = "; ".join(result.get("errors", []) or []) or str(result.get("error", "")) or "no detail"
    return ToolResult(f"sidecar status {status}: {detail}", is_error=True)


# --- registry construction -----------------------------------------------------

_READ_SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
_GREP_SCHEMA = {
    "type": "object",
    "properties": {
        "pattern": {"type": "string"},
        "path": {"type": "string"},
        "max_matches": {"type": "integer"},
    },
    "required": ["pattern"],
}
_LIST_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
}
_WRITE_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
    "required": ["path", "content"],
}
_EDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "old_string": {"type": "string"},
        "new_string": {"type": "string"},
    },
    "required": ["path", "old_string", "new_string"],
}
_TASK_SCHEMA = {
    "type": "object",
    "properties": {"agent": {"type": "string"}, "prompt": {"type": "string"}},
    "required": ["agent", "prompt"],
}
_CODEX_SCHEMA = {
    "type": "object",
    "properties": {"prompt": {"type": "string"}, "timeout_ms": {"type": "integer"}},
    "required": ["prompt"],
}


def builtin_tools(include_codex: bool = False, include_task: bool = True) -> list[Tool]:
    """The default tool set.

    ``CodexReadOnly`` is only registered when a sidecar socket was configured
    (the runtime passes ``include_codex=True`` only in that case). ``Task``
    is only registered when the runtime has subagents configured.
    """
    tools = [
        Tool("Read", "Read a text file inside the workspace (capped at 256 KiB).", "read", _READ_SCHEMA, handle_read),
        Tool("Grep", "Regex-search text files in the workspace (capped at 200 matches).", "read", _GREP_SCHEMA, handle_grep),
        Tool("List", "List workspace entries (capped at 500 entries).", "read", _LIST_SCHEMA, handle_list),
        Tool("Write", "Create or overwrite a text file inside the workspace.", "edit", _WRITE_SCHEMA, handle_write),
        Tool("Edit", "Replace a unique string in a workspace file.", "edit", _EDIT_SCHEMA, handle_edit),
    ]
    if include_task:
        tools.append(
            Tool(
                "Task",
                "Delegate a bounded task to a configured subagent with its own context and tool set.",
                "delegate",
                _TASK_SCHEMA,
                handle_task,
            )
        )
    if include_codex:
        tools.append(
            Tool(
                "CodexReadOnly",
                "Run a prompt through the northstar-codex-sidecar (read-only Codex execution over a local Unix socket).",
                "exec",
                _CODEX_SCHEMA,
                handle_codex,
            )
        )
    return tools
