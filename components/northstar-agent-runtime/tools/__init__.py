"""Tool registry, uniform handler signature, and the sandbox every path crosses.

Two invariants live here and both are load-bearing:

**One handler shape.** Every tool is ``handler(payload: dict, ctx: ToolContext)``.
Registration inspects the signature and refuses a handler whose parameters are
reversed or misnamed, because a registry where one tool takes ``(payload, ctx)``
and another takes ``(ctx, payload)`` fails at the worst possible moment - inside
a real run, with the arguments swapped.

**Symlink-first containment.** A path is resolved with ``realpath`` *before* the
workspace-containment check, and the nearest existing ancestor is resolved so a
not-yet-created file is checked too. Checking the unresolved string first is how
``notes/../../../../etc/passwd`` or a workspace symlink to ``/`` walks straight
out of the sandbox.
"""
from __future__ import annotations

import inspect
import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

MAX_READ_BYTES = 256 * 1024
MAX_GREP_MATCHES = 200
MAX_LIST_ENTRIES = 500
MAX_GREP_FILE_BYTES = 2 * 1024 * 1024
MAX_GREP_FILES = 4000
# Slightly above the read cap so Read is bounded by its own documented 256 KB limit
# rather than by result framing; grep/list caps are far smaller than this.
MAX_TOOL_RESULT_CHARS = 300_000
MAX_LINE_PREVIEW = 240

ToolKind = Literal["read", "edit", "exec", "task", "network", "other"]


class ToolAccessError(RuntimeError):
    """Raised by the sandbox; converted into an errored tool_result, never a crash."""


class ToolInputError(ValueError):
    """Raised for a malformed tool payload; reported to the model as an error."""


@dataclass(frozen=True)
class ToolLimits:
    max_read_bytes: int = MAX_READ_BYTES
    max_grep_matches: int = MAX_GREP_MATCHES
    max_list_entries: int = MAX_LIST_ENTRIES
    max_grep_file_bytes: int = MAX_GREP_FILE_BYTES
    max_grep_files: int = MAX_GREP_FILES
    max_result_chars: int = MAX_TOOL_RESULT_CHARS
    #: Paths a mutating tool may not write through, relative to the workspace.
    #:
    #: ``.git`` is repository metadata. ``.northstar`` is the *run's own
    #: governance*: ``config.toml`` (the policy that gates it), ``agents/*.md``
    #: (subagent definitions) and ``skills/*/SKILL.md`` (prompt content). A tool
    #: that could rewrite any of those could rewrite the rules that constrain it,
    #: which turns repository configuration into a self-service escalation and
    #: persistence path (an agent edits the deny list, the *next* run obeys the
    #: edited one). This is the configuration-based sandbox escape the 2026 agent
    #: hardening guidance calls out ("treat sandbox configuration as immutable").
    #:
    #: A policy file may only ever tighten, so a rewrite cannot install
    #: ``bypassPermissions`` - it can silently drop tightenings, plant poisoned
    #: instructions, or corrupt the file so every later run refuses to start. All
    #: three are refused here. A host that genuinely wants the agent to edit
    #: governance narrows the set explicitly (``--allow-policy-writes``).
    protected_prefixes: tuple[str, ...] = (".git", ".northstar")
    follow_symlinks: bool = True

    def __post_init__(self) -> None:
        if self.max_read_bytes <= 0 or self.max_grep_matches <= 0 or self.max_list_entries <= 0:
            raise ValueError("tool limits must be positive")


@dataclass(frozen=True)
class ToolContext:
    """Read-only environment handed to every handler."""

    session_id: str = ""
    agent: str = "main"
    depth: int = 0
    turn_index: int = 0
    sandbox: "ToolSandbox | None" = None
    limits: ToolLimits = field(default_factory=ToolLimits)
    services: Mapping[str, Any] = field(default_factory=dict)

    def resolve(self, raw: Any, *, for_write: bool = False, must_exist: bool = False) -> Path:
        if self.sandbox is None:
            raise ToolAccessError("this tool context has no workspace sandbox")
        return self.sandbox.resolve(raw, for_write=for_write, must_exist=must_exist)

    def relative(self, path: Path) -> str:
        """Workspace-relative display path; never leaks a resolved absolute path into output."""
        if self.sandbox is None:
            return str(path)
        return self.sandbox.relative(path)

    def service(self, name: str) -> Any:
        return self.services.get(name)


@dataclass(frozen=True)
class ToolResult:
    """What a handler returns. ``is_error`` is the only failure signal the loop reads."""

    content: Any = ""
    is_error: bool = False
    truncated: bool = False
    data: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def error(message: str, **data: Any) -> "ToolResult":
        return ToolResult(content=message, is_error=True, data=dict(data))

    @staticmethod
    def ok(content: Any = "", **data: Any) -> "ToolResult":
        return ToolResult(content=content, data=dict(data))

    def text(self) -> str:
        from providers.base import flatten_result_content as _flatten_result_content  # no import cycle

        if isinstance(self.content, str):
            return self.content
        if isinstance(self.content, (list, tuple)):
            return _flatten_result_content(self.content)
        if isinstance(self.content, dict):
            return json.dumps(self.content, ensure_ascii=False, sort_keys=True, default=str)
        return str(self.content)

    def as_block(self, tool_use_id: str, *, max_chars: int = MAX_TOOL_RESULT_CHARS) -> Any:
        from providers.base import ToolResultBlock

        text = self.text()
        truncated = self.truncated
        if max_chars > 0 and len(text) > max_chars:
            text = text[:max_chars] + f"\n[truncated {len(text) - max_chars} chars by the runtime result cap]"
            truncated = True
        return ToolResultBlock(tool_use_id=tool_use_id, content=text, is_error=self.is_error)


@dataclass(frozen=True)
class ToolSpec:
    """One callable capability."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], ToolContext], Any]
    kind: ToolKind = "read"
    is_mutating: bool | None = None
    #: Delegation-only tools are never executed directly by the loop.
    is_delegation: bool = False
    #: Tools the model may always call regardless of workspace availability.
    needs_workspace: bool = True

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("tool name must be a non-empty string")
        if self.is_mutating is None:
            object.__setattr__(self, "is_mutating", self.kind in {"edit", "exec", "network", "other"})
        _validate_handler_signature(self.name, self.handler)

    @property
    def read_only(self) -> bool:
        return not bool(self.is_mutating)

    def to_api(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema or {"type": "object", "properties": {}},
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "is_mutating": bool(self.is_mutating),
            "is_delegation": self.is_delegation,
        }


def _validate_handler_signature(name: str, handler: Any) -> None:
    """Guard against the ``(ctx, payload)`` swap before it can bite at runtime."""
    if not callable(handler):
        raise TypeError(f"tool {name}: handler must be callable")
    try:
        parameters = list(inspect.signature(handler).parameters.values())
    except (TypeError, ValueError):  # pragma: no cover - builtins without signatures
        return
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    if not positional:
        raise TypeError(f"tool {name}: handler must accept (payload, ctx)")
    names = [parameter.name for parameter in positional[:2]]
    if names[:1] == ["ctx"]:
        raise TypeError(
            f"tool {name}: handler parameters are (ctx, payload); the registry requires "
            "(payload, ctx) for every tool"
        )
    if len(positional) < 2 and not any(
        parameter.kind == parameter.VAR_POSITIONAL for parameter in parameters
    ):
        raise TypeError(f"tool {name}: handler must accept (payload, ctx)")


class ToolSandbox:
    """Workspace containment with symlink resolution ahead of the check."""

    def __init__(self, workspace: str | os.PathLike[str], *, limits: ToolLimits | None = None) -> None:
        self.limits = limits or ToolLimits()
        self.root = Path(workspace).expanduser()
        if not str(self.root):
            raise ValueError("workspace root must not be empty")
        self.root_real = Path(os.path.realpath(str(self.root)))

    @property
    def exists(self) -> bool:
        return self.root_real.is_dir()

    def _within(self, resolved: Path) -> bool:
        try:
            resolved.relative_to(self.root_real)
        except ValueError:
            return False
        return True

    def resolve(self, raw: Any, *, for_write: bool = False, must_exist: bool = False) -> Path:
        if not isinstance(raw, str):
            raise ToolInputError(f"path must be a string, got {type(raw).__name__}")
        candidate = raw.strip()
        if not candidate:
            raise ToolInputError("path must not be empty")
        if "\x00" in candidate:
            raise ToolInputError("path contains a NUL byte")
        path = Path(candidate)
        if not path.is_absolute():
            path = self.root / path
        # Collapse ".." lexically first. Left in place, ".." segments are resolved
        # by the kernel against whatever the components turn out to be, so the
        # containment check and the eventual open() could disagree.
        path = Path(os.path.normpath(str(path)))
        resolved = self._realpath_partial(path)
        if not self._within(resolved):
            raise ToolAccessError(
                f"path escapes the run workspace after following symlinks: {candidate!r} resolves to "
                f"{resolved} which is outside {self.root_real}"
            )
        if for_write:
            self._check_protected(resolved)
        if must_exist and not resolved.exists():
            raise ToolInputError(f"no such path inside the workspace: {candidate}")
        return resolved

    def _realpath_partial(self, path: Path) -> Path:
        """``realpath`` the nearest existing ancestor, then re-attach the tail.

        A write target usually does not exist yet, so resolving only the full path
        would skip the symlink check on every existing parent component.
        """
        tail: list[str] = []
        current = path
        while not current.exists():
            parent = current.parent
            if parent == current:
                break
            tail.append(current.name)
            current = parent
        real = Path(os.path.realpath(str(current)))
        for name in reversed(tail):
            real = real / name
        # The re-attached tail can itself contain ".." (from a path that pointed at
        # a missing directory), so normalise once more before returning.
        return Path(os.path.normpath(str(real)))

    def _check_protected(self, resolved: Path) -> None:
        try:
            relative = resolved.relative_to(self.root_real)
        except ValueError:  # pragma: no cover - containment already ran
            return
        parts = relative.parts
        for prefix in self.limits.protected_prefixes:
            head = Path(prefix).parts
            if len(parts) < len(head) or parts[: len(head)] != head:
                continue
            if prefix == ".northstar":
                # Name the escape hatch here: this denial is the one an operator
                # will legitimately want to override, per run, from the CLI.
                raise ToolAccessError(
                    f"writes under {prefix!r} are refused: that tree holds the run's own "
                    "governance (policy, agents, skills) and an agent must not rewrite the "
                    "rules that gate it; pass --allow-policy-writes if a human intends this"
                )
            raise ToolAccessError(
                f"writes under {prefix!r} are refused: that tree holds repository metadata "
                "the runtime must not rewrite"
            )

    def relative(self, path: Path) -> str:
        try:
            return str(Path(os.path.realpath(str(path))).relative_to(self.root_real))
        except ValueError:  # pragma: no cover - defensive
            return str(path)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def _first_doc_line(function: Any) -> str:
    doc = getattr(function, "__doc__", None) or ""
    return doc.strip().splitlines()[0].strip() if doc.strip() else ""


class ToolRegistry:
    """Name-keyed tool set with deterministic ordering."""

    def __init__(self, specs: Iterable[ToolSpec] = ()) -> None:
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ToolSpec, *, replace_existing: bool = False) -> ToolSpec:
        if not isinstance(spec, ToolSpec):
            raise TypeError("registry accepts ToolSpec instances")
        if spec.name in self._specs and not replace_existing:
            raise ValueError(f"tool {spec.name!r} is already registered; pass replace_existing=True to override")
        self._specs[spec.name] = spec
        return spec

    def tool(
        self,
        name: str,
        *,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        kind: ToolKind = "read",
        is_mutating: bool | None = None,
    ) -> Callable[[Callable[[dict[str, Any], ToolContext], Any]], ToolSpec]:
        def decorate(function: Callable[[dict[str, Any], ToolContext], Any]) -> ToolSpec:
            spec = ToolSpec(
                name=name,
                description=description or _first_doc_line(function),
                input_schema=input_schema or {"type": "object", "properties": {}},
                handler=function,
                kind=kind,
                is_mutating=is_mutating,
            )
            self.register(spec)
            return spec

        return decorate

    def unregister(self, name: str) -> bool:
        return self._specs.pop(name, None) is not None

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def require(self, name: str) -> ToolSpec:
        spec = self._specs.get(name)
        if spec is None:
            raise KeyError(f"unknown tool {name!r}; registered tools: {', '.join(self.names())}")
        return spec

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(self._specs[key] for key in sorted(self._specs))

    def subset(self, names: Sequence[str], *, missing_ok: bool = True) -> "ToolRegistry":
        """Tool set for a subagent: only what the agent declaration lists."""
        picked = ToolRegistry()
        for name in names:
            spec = self._specs.get(name)
            if spec is None:
                if not missing_ok:
                    raise KeyError(f"tool {name!r} is not registered")
                continue
            picked.register(spec)
        return picked

    def missing(self, names: Sequence[str]) -> tuple[str, ...]:
        return tuple(name for name in names if name not in self._specs)

    def to_api(self) -> tuple[dict[str, Any], ...]:
        return tuple(spec.to_api() for spec in self.specs())

    def kinds(self) -> dict[str, str]:
        return {spec.name: spec.kind for spec in self._specs.values()}

    def describe(self) -> list[dict[str, Any]]:
        return [spec.as_dict() for spec in self.specs()]

    def __iter__(self):
        return iter(self.specs())


# ---------------------------------------------------------------------------
# Built-in tools
# ---------------------------------------------------------------------------

_OBJECT_SCHEMA = {"type": "object", "properties": {}}


def _schema(properties: Mapping[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    payload: dict[str, Any] = {"type": "object", "properties": dict(properties)}
    if required:
        payload["required"] = list(required)
    return payload


def read_file(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Read at most ``limits.max_read_bytes`` of a workspace file."""
    path = ctx.resolve(payload.get("path"), must_exist=True)
    limit = int(payload.get("max_bytes") or ctx.limits.max_read_bytes)
    limit = max(1, min(limit, ctx.limits.max_read_bytes))
    if not path.is_file():
        return ToolResult.error(f"not a file: {payload.get('path')}")
    size = path.stat().st_size
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    truncated = len(raw) > limit or size > limit
    text = raw[:limit].decode("utf-8", "replace")
    if "\x00" in text:
        return ToolResult(
            content=f"[binary file, {size} bytes: {ctx.relative(path)} - not shown]",
            data={"bytes": 0, "truncated": truncated, "binary": True},
        )
    content = text
    if truncated:
        # Marked on both ends: a long tail can be cut again by the result cap, and
        # a model that only reads the head must still know it is holding a prefix.
        content = (
            f"[first {limit} of {size} bytes; the runtime read cap truncated this file]\n"
            + content
            + f"\n[truncated at {limit} of {size} bytes by the runtime read cap; "
            "re-read with an explicit max_bytes or use Grep to search the rest]"
        )
    return ToolResult(
        content=content,
        truncated=truncated,
        data={"path": ctx.relative(path), "bytes": min(limit, size), "size": size, "truncated": truncated},
    )


def write_file(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Create or overwrite a workspace file."""
    path = ctx.resolve(payload.get("path"), for_write=True)
    content = payload.get("content", "")
    if not isinstance(content, str):
        return ToolResult.error("content must be a string")
    if payload.get("mode") == "append":
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(content)
        return ToolResult(content=f"appended {len(content)} chars to {ctx.relative(path)}", data={"path": ctx.relative(path), "bytes": len(content)})
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return ToolResult(
        content=f"wrote {len(content)} chars to {ctx.relative(path)}",
        data={"path": ctx.relative(path), "bytes": len(content), "created": not path.is_file()},
    )


def edit_file(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Replace an exact string; ambiguous matches are refused, not guessed."""
    path = ctx.resolve(payload.get("path"), for_write=True, must_exist=True)
    old = payload.get("old_string", payload.get("old_text", ""))
    new = payload.get("new_string", payload.get("new_text", ""))
    if not isinstance(old, str) or not old:
        return ToolResult.error("old_string must be a non-empty string")
    if not isinstance(new, str):
        return ToolResult.error("new_string must be a string")
    text = path.read_text(encoding="utf-8", errors="replace")
    count = text.count(old)
    if count == 0:
        return ToolResult.error(f"old_string not found in {ctx.relative(path)}")
    if count > 1 and not payload.get("replace_all", False):
        return ToolResult.error(
            f"old_string matches {count} places in {ctx.relative(path)}; make it unique or pass replace_all=true"
        )
    updated = text.replace(old, new) if payload.get("replace_all") else text.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    return ToolResult(
        content=f"edited {ctx.relative(path)} ({count} match(es), {1 if not payload.get('replace_all') else count} replaced)",
        data={"path": ctx.relative(path), "matches": count},
    )


def list_dir(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """List up to ``limits.max_list_entries`` entries of a workspace directory."""
    raw = payload.get("path", ".")
    path = ctx.resolve(raw if raw is not None else ".", must_exist=True)
    if not path.is_dir():
        return ToolResult.error(f"not a directory: {raw}")
    cap = ctx.limits.max_list_entries
    limit = int(payload.get("limit") or cap)
    limit = max(1, min(limit, cap))
    entries: list[dict[str, Any]] = []
    truncated = False
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(entries) >= limit:
                    truncated = True
                    break
                try:
                    stat_result = entry.stat(follow_symlinks=False)
                    kind = "dir" if entry.is_dir(follow_symlinks=False) else ("link" if entry.is_symlink() else "file")
                    size = stat_result.st_size if kind == "file" else 0
                except OSError:
                    kind, size = "unknown", 0
                entries.append({"name": entry.name, "kind": kind, "bytes": size})
    except OSError as error:
        return ToolResult.error(f"cannot list {raw}: {error}")
    entries.sort(key=lambda item: (item["kind"] != "dir", item["name"]))
    rendered = "\n".join(
        f"{item['kind'][0]} {item['bytes']:>9} {item['name']}" + ("/" if item["kind"] == "dir" else "")
        for item in entries
    )
    if truncated:
        rendered += f"\n[truncated at {limit} entries by the runtime listing cap]"
    return ToolResult(
        content=rendered or "(empty directory)",
        truncated=truncated,
        data={"path": ctx.relative(path), "entries": len(entries), "truncated": truncated},
    )


def grep_files(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Regex search over workspace text files, capped at ``limits.max_grep_matches``."""
    pattern = payload.get("pattern", payload.get("regex", ""))
    if not isinstance(pattern, str) or not pattern:
        return ToolResult.error("pattern must be a non-empty string")
    try:
        flags = re.IGNORECASE if payload.get("ignore_case") else 0
        compiled = re.compile(pattern, flags)
    except re.error as error:
        return ToolResult.error(f"invalid regular expression: {error}")
    root = ctx.resolve(payload.get("path", ".") or ".")
    cap = ctx.limits.max_grep_matches
    limit = int(payload.get("max_matches") or cap)
    limit = max(1, min(limit, cap))
    matches: list[str] = []
    scanned = 0
    truncated = False
    targets: list[Path] = []
    if root.is_file():
        targets = [root]
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [name for name in sorted(dirnames) if name not in {".git", "__pycache__", "node_modules"}]
            for filename in sorted(filenames):
                targets.append(Path(dirpath) / filename)
                if len(targets) >= ctx.limits.max_grep_files:
                    truncated = True
                    break
            if truncated:
                break
    else:
        return ToolResult.error(f"no such path: {payload.get('path', '.')}")
    globber = payload.get("glob")
    glob_re = _glob_to_regex(globber) if isinstance(globber, str) and globber else None
    for target in targets:
        if glob_re is not None and not glob_re.search(ctx.relative(target)):
            continue
        scanned += 1
        try:
            stat_result = target.stat()
            if stat_result.st_size > ctx.limits.max_grep_file_bytes:
                continue
            with open(target, "rb") as handle:
                raw = handle.read(ctx.limits.max_grep_file_bytes)
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        relative = ctx.relative(target)
        for line_number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), start=1):
            if not compiled.search(line):
                continue
            if len(matches) >= limit:
                truncated = True
                break
            preview = line.strip()
            if len(preview) > MAX_LINE_PREVIEW:
                preview = preview[:MAX_LINE_PREVIEW] + "..."
            matches.append(f"{relative}:{line_number}: {preview}")
        if truncated:
            break
    body = "\n".join(matches) if matches else "no matches"
    if truncated:
        body += f"\n[truncated at {limit} matches by the runtime grep cap]"
    return ToolResult(
        content=body,
        truncated=truncated,
        data={"matches": len(matches), "files_scanned": scanned, "truncated": truncated},
    )


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    escaped: list[str] = []
    index = 0
    while index < len(glob):
        char = glob[index]
        if char == "*":
            if glob[index : index + 2] == "**":
                escaped.append(".*")
                index += 2
                continue
            escaped.append("[^/]*")
        elif char == "?":
            escaped.append("[^/]")
        elif char in ".+^$(){}[]|\\":
            escaped.append("\\" + char)
        else:
            escaped.append(char)
        index += 1
    return re.compile("^" + "".join(escaped) + "$")


def describe_tools(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Self-inspection tool: what may I call, and how is it governed?"""
    registry: ToolRegistry | None = ctx.service("registry")
    if registry is None:
        return ToolResult.error("no tool registry is attached to this context")
    return ToolResult(
        content=json.dumps(registry.describe(), ensure_ascii=False, indent=2, sort_keys=True),
        data={"tools": list(registry.names())},
    )


BUILTIN_TOOLS: tuple[str, ...] = ("Read", "Write", "Edit", "LS", "Grep", "DescribeTools")


def build_default_registry(include_describe: bool = True) -> ToolRegistry:
    """The workspace tool set every run starts from."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="Read",
            description="Read a workspace text file. Output is capped; re-read with max_bytes or use Grep for the remainder.",
            input_schema=_schema(
                {
                    "path": {"type": "string", "description": "Path relative to the run workspace"},
                    "max_bytes": {"type": "integer", "description": "Optional smaller cap; never exceeds the runtime cap"},
                },
                ["path"],
            ),
            handler=read_file,
            kind="read",
        )
    )
    registry.register(
        ToolSpec(
            name="Write",
            description="Create or overwrite a workspace text file.",
            input_schema=_schema(
                {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "mode": {"type": "string", "enum": ["write", "append"]},
                },
                ["path", "content"],
            ),
            handler=write_file,
            kind="edit",
        )
    )
    registry.register(
        ToolSpec(
            name="Edit",
            description="Replace one exact string in a workspace file. Ambiguous matches are refused.",
            input_schema=_schema(
                {
                    "path": {"type": "string"},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"},
                    "replace_all": {"type": "boolean"},
                },
                ["path", "old_string", "new_string"],
            ),
            handler=edit_file,
            kind="edit",
        )
    )
    registry.register(
        ToolSpec(
            name="LS",
            description="List a workspace directory (capped).",
            input_schema=_schema({"path": {"type": "string"}, "limit": {"type": "integer"}}),
            handler=list_dir,
            kind="read",
        )
    )
    registry.register(
        ToolSpec(
            name="Grep",
            description="Regular-expression search across workspace text files (capped matches).",
            input_schema=_schema(
                {
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                    "glob": {"type": "string"},
                    "ignore_case": {"type": "boolean"},
                    "max_matches": {"type": "integer"},
                },
                ["pattern"],
            ),
            handler=grep_files,
            kind="read",
        )
    )
    if include_describe:
        registry.register(
            ToolSpec(
                name="DescribeTools",
                description="Report the tools available to this agent and how each is classified.",
                input_schema=_schema({}),
                handler=describe_tools,
                kind="read",
                needs_workspace=False,
            )
        )
    return registry


def codex_tool_spec() -> ToolSpec:
    """Schema for the sidecar-delegated tool (registered only with a socket)."""
    from sidecar_client import SIDECAR_MAX_PROMPT_CHARS, SIDECAR_MIN_TIMEOUT_MS

    def handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
        client = ctx.service("sidecar")
        if client is None:
            return ToolResult.error("no sidecar client is attached to this context")
        prompt = payload.get("prompt", "")
        timeout_ms = payload.get("timeout_ms")
        return client.execute_tool(prompt=prompt, timeout_ms=timeout_ms)

    return ToolSpec(
        name="CodexReadOnly",
        description=(
            "Delegate a read-only question to the Northstar Codex sidecar over its Unix socket. "
            f"The prompt is capped at {SIDECAR_MAX_PROMPT_CHARS} characters and Codex runs "
            "--sandbox read-only --ephemeral; the runtime never holds model credentials."
        ),
        input_schema=_schema(
            {
                "prompt": {"type": "string", "description": "Instruction for Codex, capped by the sidecar"},
                "timeout_ms": {
                    "type": "integer",
                    "minimum": SIDECAR_MIN_TIMEOUT_MS,
                    "description": "Sidecar execution deadline in milliseconds",
                },
            },
            ["prompt"],
        ),
        handler=handler,
        # Read-only by construction: execution and sandboxing are the sidecar's job.
        kind="read",
        is_mutating=False,
    )


def truncate_text(text: str, limit: int = MAX_TOOL_RESULT_CHARS) -> tuple[str, bool]:
    if limit > 0 and len(text) > limit:
        return text[:limit] + f"\n[truncated {len(text) - limit} chars]", True
    return text, False


__all__ = [
    "BUILTIN_TOOLS",
    "MAX_GREP_MATCHES",
    "MAX_LIST_ENTRIES",
    "MAX_READ_BYTES",
    "MAX_TOOL_RESULT_CHARS",
    "ToolAccessError",
    "ToolContext",
    "ToolInputError",
    "ToolKind",
    "ToolLimits",
    "ToolRegistry",
    "ToolResult",
    "ToolSandbox",
    "ToolSpec",
    "build_default_registry",
    "codex_tool_spec",
    "describe_tools",
    "edit_file",
    "grep_files",
    "list_dir",
    "read_file",
    "truncate_text",
    "write_file",
]
