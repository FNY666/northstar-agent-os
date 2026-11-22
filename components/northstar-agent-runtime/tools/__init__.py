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

import copy
import inspect
import hashlib
import json
import os
import re
import errno
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

MAX_READ_BYTES = 256 * 1024
MAX_GREP_MATCHES = 200
MAX_LIST_ENTRIES = 500
MAX_GREP_FILE_BYTES = 2 * 1024 * 1024
MAX_GREP_FILES = 4000
MAX_GREP_TREE_ENTRIES = 16_000
# Slightly above the read cap so Read is bounded by its own documented 256 KB limit
# rather than by result framing; grep/list caps are far smaller than this.
MAX_TOOL_RESULT_CHARS = 300_000
MAX_TOOL_RESULT_NESTING = 128
MAX_LINE_PREVIEW = 240
MAX_PROVENANCE_FIELD_CHARS = 256
MAX_WORKSPACE_XATTR_COUNT = 128
MAX_WORKSPACE_XATTR_BYTES = 1024 * 1024
_WORKSPACE_XATTRS_TO_PRESERVE = frozenset({"system.posix_acl_access", "security.selinux"})
_WORKSPACE_XATTRS_CONTENT_BOUND = frozenset({"security.capability", "security.ima", "security.evm"})


def _result_fits_text_budget(value: Any, limit: int, *, text_block_type: type) -> bool:
    """Bound work before rendering structured tool output into a transcript string."""
    pending = [(value, 0)]
    seen: set[int] = set()
    size = 0
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 50_000 or depth > MAX_TOOL_RESULT_NESTING:
            return False
        if isinstance(current, str):
            addition = _json_string_size(current, limit - size)
            if addition > limit - size:
                return False
            size += addition
        elif current is None or isinstance(current, (bool, float)):
            size += 32
        elif isinstance(current, int):
            # JSON's decimal rendering of a huge integer can be much larger
            # than the integer object's fixed overhead. Bound digits before
            # calling json.dumps; 0.30103 is a slight upper approximation of
            # log10(2), so this estimate never understates decimal length.
            bits = current.bit_length()
            decimal_digits = (bits * 30_103) // 100_000 + 1
            size += decimal_digits + (1 if current < 0 else 0)
        elif isinstance(current, text_block_type):
            size += len(current.text)
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                return False
            if nodes + len(current) > 50_000:
                return False
            seen.add(identity)
            size += len(current) + 2
            pending.extend((child, depth + 1) for child in current)
        elif isinstance(current, dict):
            identity = id(current)
            if identity in seen:
                return False
            if nodes + len(current) > 50_000:
                return False
            seen.add(identity)
            size += len(current) * 4 + 2
            for key, child in current.items():
                if not isinstance(key, str):
                    return False
                addition = _json_string_size(key, limit - size)
                if addition > limit - size:
                    return False
                size += addition
                pending.append((child, depth + 1))
        else:
            # Arbitrary objects can have expensive or side-effecting __str__.
            return False
        if size > limit:
            return False
    return True


def _json_string_size(value: str, remaining: int) -> int:
    """Conservative character count for one ensure_ascii=False JSON string."""
    if len(value) + 2 > remaining:
        return remaining + 1
    size = 2  # opening and closing quotes
    for char in value:
        codepoint = ord(char)
        size += 6 if codepoint < 0x20 else (2 if char in {'"', "\\"} else 1)
        if size > remaining:
            return remaining + 1
    return size

ToolKind = Literal["read", "edit", "exec", "task", "network", "other"]


class ToolAccessError(RuntimeError):
    """Raised by the sandbox; converted into an errored tool_result, never a crash."""


class ToolWriteDenied(ToolAccessError):
    """A write target was refused during path preflight, before mutation began."""


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
    #: Host-supplied current viewers used by the workspace-memory ACL. Channel
    #: adapters must authenticate them before constructing this value. Empty
    #: means that only an explicit public grant may match.
    memory_viewers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.max_read_bytes <= 0 or self.max_grep_matches <= 0 or self.max_list_entries <= 0:
            raise ValueError("tool limits must be positive")
        if not isinstance(self.memory_viewers, tuple) or any(
            not isinstance(viewer, str) or not viewer or viewer != viewer.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in viewer)
            for viewer in self.memory_viewers
        ) or len(set(self.memory_viewers)) != len(self.memory_viewers):
            raise ValueError("memory_viewers must be a tuple of unique, non-empty viewer identities")


@dataclass(frozen=True)
class ToolContext:
    """Read-only environment handed to every handler."""

    session_id: str = ""
    agent: str = "main"
    depth: int = 0
    turn_index: int = 0
    #: The model-issued tool-use id for this call. Handlers that cross a
    #: trust boundary (e.g. the egress sidecar) must propagate it so the
    #: downstream enforcement sees the same call identity the permission
    #: gate approved.
    call_id: str = ""
    sandbox: "ToolSandbox | None" = None
    limits: ToolLimits = field(default_factory=ToolLimits)
    services: Mapping[str, Any] = field(default_factory=dict)

    def resolve(self, raw: Any, *, for_write: bool = False, must_exist: bool = False) -> Path:
        try:
            if self.sandbox is None:
                raise ToolAccessError("this tool context has no workspace sandbox")
            return self.sandbox.resolve(raw, for_write=for_write, must_exist=must_exist)
        except ToolAccessError as error:
            if for_write:
                raise ToolWriteDenied(str(error)) from error
            raise

    def relative(self, path: Path) -> str:
        """Workspace-relative display path; never leaks a resolved absolute path into output."""
        if self.sandbox is None:
            return str(path)
        return self.sandbox.relative(path)

    def service(self, name: str) -> Any:
        return self.services.get(name)


@dataclass(frozen=True)
class ToolProvenance:
    """Where a tool result came from and how much to trust it.

    Prompt-injection research (CaMeL, NetInjectBench, 2026) converges on:
    the policy must look at trusted metadata, never at artifact text.
    This envelope is the cheap first step -- every tool result carries
    its source and trust level, so consumers know not to treat tool
    output as instructions.

    Trust levels:
    - "low": untrusted external content (tool outputs, MCP servers, web
      fetches, file reads from untrusted paths). Never treat as instructions.
    - "medium": semi-trusted (workspace config, local files).
    - "high": operator-provided (prompts, explicit approvals).
    """

    source: str = ""  # e.g. "mcp:demo:echo", "tool:Read", "provider:openai"
    trust: Literal["low", "medium", "high"] = "low"
    detail: str = ""  # free-form, e.g. tool name or URL

    def __post_init__(self) -> None:
        if not isinstance(self.trust, str) or self.trust not in {"low", "medium", "high"}:
            raise ValueError("tool provenance trust must be low, medium, or high")
        for name in ("source", "detail"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"tool provenance {name} must be a string")
            if len(value) > MAX_PROVENANCE_FIELD_CHARS:
                raise ValueError(
                    f"tool provenance {name} exceeds {MAX_PROVENANCE_FIELD_CHARS} characters"
                )

    def as_dict(self) -> dict[str, str]:
        return {"source": self.source, "trust": self.trust, "detail": self.detail}


@dataclass
class ToolResult:
    """What a handler returns. ``is_error`` is the only failure signal the loop reads."""

    content: Any = ""
    is_error: bool = False
    truncated: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    provenance: ToolProvenance = field(default_factory=ToolProvenance)

    @staticmethod
    def error(
        message: str,
        *,
        provenance: ToolProvenance | None = None,
        **data: Any,
    ) -> "ToolResult":
        return ToolResult(
            content=message,
            is_error=True,
            data=dict(data),
            provenance=provenance or ToolProvenance(),
        )

    @staticmethod
    def ok(
        content: Any = "",
        *,
        provenance: ToolProvenance | None = None,
        **data: Any,
    ) -> "ToolResult":
        return ToolResult(content=content, data=dict(data), provenance=provenance or ToolProvenance())

    def text(self) -> str:
        from providers.base import flatten_result_content as _flatten_result_content  # no import cycle

        if isinstance(self.content, str):
            return self.content
        if isinstance(self.content, (list, tuple)):
            return _flatten_result_content(self.content)
        if isinstance(self.content, dict):
            return json.dumps(self.content, ensure_ascii=False, sort_keys=True, default=str)
        return str(self.content)

    def as_block_with_status(
        self, tool_use_id: str, *, max_chars: int = MAX_TOOL_RESULT_CHARS
    ) -> tuple[Any, bool]:
        """Build the bounded provider block and report truncation/omission."""
        from providers.base import TextBlock, ToolResultBlock

        # Do not flatten/JSON-encode an arbitrarily large plugin result only
        # to slice it afterwards. Strings can be sliced directly; structured
        # values are traversed with a node and size ceiling before serialization.
        effective_cap = min(max_chars if max_chars > 0 else MAX_TOOL_RESULT_CHARS, MAX_TOOL_RESULT_CHARS)
        structured_omitted = False
        if isinstance(self.content, str):
            text = self.content
        elif _result_fits_text_budget(self.content, effective_cap, text_block_type=TextBlock):
            text = self.text()
        else:
            text = "[structured tool result omitted: runtime result cap exceeded]"
            structured_omitted = True
        truncated = self.truncated or structured_omitted
        provenance = self.provenance
        # Keep JSON payloads byte-for-byte usable by sidecars and structured tools.
        # For ordinary prose, make provenance explicit at the model boundary so
        # untrusted content remains visibly labeled in the conversation.
        structured = False
        json_probe_limit = effective_cap
        if len(text) <= json_probe_limit:
            try:
                json.loads(text)
                structured = True
            except (TypeError, ValueError):
                pass
        header = ""
        if not structured and (provenance.source or provenance.detail):
            header = (
                "[Northstar tool result metadata: "
                + json.dumps(
                    {"source": provenance.source, "trust": provenance.trust, "detail": provenance.detail},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "]\n"
            )
        if len(header) > effective_cap:
            header = f"[Northstar tool result trust={provenance.trust}]\n"
            if len(header) > effective_cap:
                header = header[:effective_cap]
        content_budget = max(0, effective_cap - len(header))
        if len(text) > content_budget:
            original_length = len(text)
            marker = f"\n[truncated {original_length} chars by the runtime result cap]"
            if len(marker) > content_budget:
                text = text[:content_budget]
            else:
                retained = content_budget - len(marker)
                marker = f"\n[truncated {original_length - retained} chars by the runtime result cap]"
                retained = max(0, content_budget - len(marker))
                marker = f"\n[truncated {original_length - retained} chars by the runtime result cap]"
                if len(marker) > content_budget:
                    text = text[:content_budget]
                else:
                    text = text[:retained] + marker
            truncated = True
        return (
            ToolResultBlock(
                tool_use_id=tool_use_id,
                content=header + text,
                is_error=self.is_error,
                provenance=(provenance.source, provenance.trust, provenance.detail),
            ),
            truncated,
        )

    def as_block(self, tool_use_id: str, *, max_chars: int = MAX_TOOL_RESULT_CHARS) -> Any:
        return self.as_block_with_status(tool_use_id, max_chars=max_chars)[0]


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
    _schema_snapshot: dict[str, Any] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("tool name must be a non-empty string")
        # Keep the caller's schema object from becoming a live mutation handle
        # after registration. The separate snapshot is the gate's authority;
        # ``input_schema`` remains a compatibility view for existing callers.
        schema = copy.deepcopy(self.input_schema)
        object.__setattr__(self, "input_schema", schema)
        object.__setattr__(self, "_schema_snapshot", copy.deepcopy(schema))
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
            "input_schema": self.schema_snapshot() or {"type": "object", "properties": {}},
        }

    def schema_snapshot(self) -> dict[str, Any]:
        """Return an isolated copy of the immutable-at-registration gate schema."""
        return copy.deepcopy(self._schema_snapshot)

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
    """Workspace containment and memory audience checks for every file tool."""

    def __init__(self, workspace: str | os.PathLike[str], *, limits: ToolLimits | None = None) -> None:
        self.limits = limits or ToolLimits()
        self.root = Path(workspace).expanduser()
        if not str(self.root):
            raise ValueError("workspace root must not be empty")
        self.root_real = Path(os.path.realpath(str(self.root)))
        self._memory_access_cache: dict[str, bool] = {}
        try:
            from memory import load_memory_audience_manifest

            self._memory_audience_entries = dict(load_memory_audience_manifest(self.root_real))
            self._memory_audience_error: str | None = None
        except (OSError, ValueError) as error:
            # A malformed policy must not make designated memory paths fall back
            # to ordinary workspace visibility. Resolve will fail closed.
            self._memory_audience_entries = {}
            self._memory_audience_error = str(error)

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
            path = self.root_real / path
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
            self._check_protected_path_alias(path, resolved)
        self._check_memory_access(path, resolved)
        if must_exist and not resolved.exists():
            raise ToolInputError(f"no such path inside the workspace: {candidate}")
        return resolved

    def _memory_relative(self, path: Path) -> str | None:
        try:
            relative = path.relative_to(self.root_real)
        except ValueError:
            return None
        relative_name = relative.as_posix()
        from memory import is_memory_write_path

        return relative_name if (
            is_memory_write_path(relative.parts) or relative_name in self._memory_audience_entries
        ) else None

    def _memory_allowed(self, path: Path, *, allow_memory_root: bool = False) -> bool:
        relative = self._memory_relative(path)
        if relative is None:
            return self._memory_audience_error is None
        if self._memory_audience_error is not None:
            return False
        if allow_memory_root and relative == ".northstar/memory":
            return True
        cached = self._memory_access_cache.get(relative)
        if cached is not None:
            return cached
        try:
            from memory import audience_grant_allows

            grant = self._memory_audience_entries.get(relative, frozenset())
            allowed = audience_grant_allows(grant, self.limits.memory_viewers)
        except (OSError, ValueError):
            allowed = False
        self._memory_access_cache[relative] = allowed
        return allowed

    def _check_memory_access(self, requested: Path, resolved: Path) -> None:
        """Gate direct Read/Write/Edit paths, including symlink aliases."""
        if self._memory_audience_error is not None:
            raise ToolAccessError(f"memory audience policy is invalid: {self._memory_audience_error}")
        requested_relative = self._memory_relative(requested)
        if requested_relative is not None:
            current = self.root_real
            for part in Path(requested_relative).parts:
                current = current / part
                if current.is_symlink():
                    raise ToolAccessError("symlinks inside workspace memory are refused")
        if not self._memory_allowed(resolved, allow_memory_root=resolved.is_dir()):
            raise ToolAccessError("workspace memory audience does not authorize this run")

    def memory_path_allowed(self, path: Path) -> bool:
        """Whether a listing/search may expose this memory path."""
        if self._memory_audience_error is not None:
            return False
        relative = self._memory_relative(path)
        if relative is None:
            return True
        if path.is_symlink():
            return False
        return self._memory_allowed(path, allow_memory_root=path.is_dir())

    def require_shell_memory_access(self) -> None:
        """Refuse Shell while memory audience rules are active.

        The process sandbox grants workspace-wide read/write access and cannot
        express this per-file ACL or protect the grant manifest. A command could
        widen its own audience, so denying Shell is the only sound fallback
        until private memories live in separate OS workspaces.
        """
        if self._memory_audience_error is not None:
            raise ToolAccessError(f"Shell is refused because memory audience policy is invalid: {self._memory_audience_error}")
        from memory import MEMORY_AUDIENCE_MANIFEST

        if (self.root_real / MEMORY_AUDIENCE_MANIFEST).exists():
            raise ToolAccessError(
                "Shell is refused while a memory audience manifest is active; the process backend can rewrite workspace files"
            )
        for relative in self._memory_audience_entries:
            path = self.root_real / relative
            if path.exists() and not self._memory_allowed(path):
                raise ToolAccessError(
                    "Shell is refused because this workspace contains memory outside the current audience"
                )
        governance = self.root_real / ".northstar"
        memory_root = governance / "memory"
        if governance.is_symlink() or memory_root.is_symlink():
            raise ToolAccessError("Shell is refused because the workspace memory tree crosses a symlink")
        if not memory_root.exists():
            return
        pending = [memory_root]
        visited = 0
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > MAX_GREP_TREE_ENTRIES:
                            raise ToolAccessError("cannot authorize Shell: memory tree exceeds the scan limit")
                        child = Path(entry.path)
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(child)
                        elif not self.memory_path_allowed(child):
                            raise ToolAccessError(
                                "Shell is refused because this workspace contains memory outside the current audience"
                            )
            except ToolAccessError:
                raise
            except OSError as error:
                raise ToolAccessError(f"cannot authorize Shell memory access: {error}") from error

    def _check_protected_path_alias(self, requested: Path, resolved: Path) -> None:
        """Do not let a symlink alias enter or leave a protected path boundary."""
        def relative(path: Path) -> tuple[str, ...] | None:
            try:
                return path.relative_to(self.root_real).parts
            except ValueError:
                return None

        requested_parts = relative(requested)
        resolved_parts = relative(resolved)
        protected_heads = {Path(prefix).parts for prefix in self.limits.protected_prefixes}
        # .northstar remains a trust boundary even when an operator explicitly
        # enables policy writes; that switch permits canonical edits, not aliases.
        protected_heads.add((".northstar",))

        def crosses_boundary(parts: tuple[str, ...] | None) -> bool:
            return parts is not None and any(
                len(parts) >= len(head) and parts[: len(head)] == head
                for head in protected_heads
            )

        if (crosses_boundary(requested_parts) or crosses_boundary(resolved_parts)) and requested_parts != resolved_parts:
            raise ToolAccessError(
                "writes cannot cross a protected-path symlink alias; use the canonical workspace path"
            )

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
        from memory import MEMORY_AUDIENCE_MANIFEST

        if parts == Path(MEMORY_AUDIENCE_MANIFEST).parts:
            raise ToolAccessError("the operator-owned memory audience manifest is immutable to file tools")
        for prefix in self.limits.protected_prefixes:
            head = Path(prefix).parts
            if len(parts) < len(head) or parts[: len(head)] != head:
                continue
            if prefix == ".northstar":
                # P4 carve-out: workspace memory is the one agent-owned note
                # store under .northstar. Policy/agents/skills stay locked.
                from memory import is_memory_write_path

                if is_memory_write_path(parts):
                    continue
                # Name the escape hatch here: this denial is the one an operator
                # will legitimately want to override, per run, from the CLI.
                raise ToolAccessError(
                    f"writes under {prefix!r} are refused: that tree holds the run's own "
                    "governance (policy, agents, skills) and an agent must not rewrite the "
                    "rules that gate it; pass --allow-policy-writes if a human intends this "
                    f"(workspace memory under {parts[0]}/memory/ is the sole carve-out)"
                )
            raise ToolAccessError(
                f"writes under {prefix!r} are refused: that tree holds repository metadata "
                "the runtime must not rewrite"
            )

    def relative(self, path: Path) -> str:
        try:
            return str(Path(path).relative_to(self.root_real)) or "."
        except ValueError:  # pragma: no cover - defensive; never leak an outside absolute path
            return "<outside workspace>"


@contextmanager
def _workspace_parent_fd(ctx: ToolContext, path: Path, *, create_parents: bool = False):
    """Open the canonical workspace parent by descriptor, rejecting raced symlinks.

    ``ToolSandbox.resolve`` remains the friendly path-policy check. This second
    check binds the actual filesystem operation to no-follow directory handles,
    closing the interval where an attacker could replace a checked parent with a
    symlink before ``open(path)``.
    """
    sandbox = ctx.sandbox
    if sandbox is None:
        raise ToolAccessError("this tool context has no workspace sandbox")
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise ToolAccessError("this host lacks no-follow directory handles for safe workspace access")
    try:
        relative = path.relative_to(sandbox.root_real)
    except ValueError as error:
        raise ToolAccessError("resolved path is outside the run workspace") from error
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ToolAccessError("workspace file path is not canonical")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current_fd = _open_directory_chain(sandbox.root_real, flags)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create_parents:
                    raise
                try:
                    os.mkdir(part, 0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ToolAccessError("workspace path changed to a symlink or non-directory during access") from error
                raise
            os.close(current_fd)
            current_fd = next_fd
        yield current_fd, parts[-1]
    finally:
        os.close(current_fd)


def _open_directory_chain(path: Path, flags: int | None = None) -> int:
    """Open an absolute directory path one no-follow component at a time.

    ``O_NOFOLLOW`` on one absolute-path ``open`` protects only its final
    component. Walking from the filesystem root pins every ancestor so a
    concurrent rename/symlink replacement cannot redirect the workspace root.
    """
    if not path.is_absolute():
        raise ToolAccessError("workspace root must be absolute")
    directory_flags = flags or (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    current_fd = os.open(path.anchor, directory_flags)
    try:
        for part in path.parts[1:]:
            try:
                next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ToolAccessError(
                        "workspace root changed to a symlink or non-directory during access"
                    ) from error
                raise
            previous_fd = current_fd
            current_fd = next_fd
            os.close(previous_fd)
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


@contextmanager
def _open_workspace_file(
    ctx: ToolContext,
    path: Path,
    flags: int,
    *,
    mode: int = 0o666,
    create_parents: bool = False,
):
    """Context-manage a file descriptor opened beneath a pinned workspace parent."""
    with _workspace_parent_fd(ctx, path, create_parents=create_parents) as (parent_fd, name):
        try:
            fd = os.open(
                name,
                flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                mode,
                dir_fd=parent_fd,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ToolAccessError("workspace file changed to a symlink during access") from error
            raise
        try:
            yield fd
        finally:
            os.close(fd)


@contextmanager
def _open_workspace_directory(ctx: ToolContext, path: Path):
    """Open a workspace directory without following any path component."""
    sandbox = ctx.sandbox
    if sandbox is None:
        raise ToolAccessError("this tool context has no workspace sandbox")
    if path == sandbox.root_real:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = _open_directory_chain(sandbox.root_real, flags)
        try:
            yield fd
        finally:
            os.close(fd)
        return
    with _workspace_parent_fd(ctx, path) as (parent_fd, name):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ToolAccessError("workspace directory changed during access") from error
            raise
        try:
            yield fd
        finally:
            os.close(fd)


def _write_workspace_file(ctx: ToolContext, path: Path, text: str, *, append: bool = False) -> None:
    """Write without following raced symlinks or modifying multiply-linked files.

    Full replacements are staged in the target directory and atomically renamed
    into place. A failed or interrupted write therefore leaves the previous file
    intact instead of exposing an empty or partial source file to the next turn.
    Append remains an in-place operation because its contract is incremental.
    """
    raw = text.encode("utf-8")
    if not append:
        _atomic_replace_workspace_file(ctx, path, raw, create_parents=True)
        return

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    with _open_workspace_file(ctx, path, flags, create_parents=not append) as fd:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ToolAccessError("workspace writes require a regular file")
        if metadata.st_nlink > 1:
            raise ToolAccessError("refusing to write a multiply-linked workspace file")
        _write_fd(fd, raw)


def _file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Fields that detect a replacement or concurrent edit of a workspace file."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _workspace_target_stat(parent_fd: int, name: str) -> os.stat_result | None:
    """Inspect a leaf without following it, rejecting non-files and hardlinks."""
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ToolAccessError("workspace writes require a regular file")
    if metadata.st_nlink > 1:
        raise ToolAccessError("refusing to write a multiply-linked workspace file")
    if (metadata.st_mode & 0o222) == 0:
        raise ToolAccessError("refusing to replace a read-only workspace file")
    return metadata


def _workspace_xattrs(fd: int) -> dict[str, bytes]:
    """Capture metadata whose meaning survives a content replacement.

    ACL and SELinux labels affect access/security and must not silently vanish.
    Unknown or content-bound attributes fail closed rather than being copied
    onto different bytes with stale semantics.
    """
    if not all(callable(getattr(os, name, None)) for name in ("listxattr", "getxattr")):
        raise ToolAccessError("this host cannot inspect workspace extended attributes safely")
    try:
        names = os.listxattr(fd)
    except TypeError as error:
        raise ToolAccessError("this host cannot inspect workspace extended attributes by descriptor") from error
    except OSError as error:
        if error.errno in {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
            return {}
        raise ToolAccessError("cannot inspect workspace file metadata before replacement") from error
    if len(names) > MAX_WORKSPACE_XATTR_COUNT:
        raise ToolAccessError("workspace file has too many extended attributes to replace safely")

    captured: dict[str, bytes] = {}
    total = 0
    for name in names:
        if name in _WORKSPACE_XATTRS_CONTENT_BOUND:
            raise ToolAccessError(f"refusing to replace a file with content-bound attribute {name!r}")
        if name not in _WORKSPACE_XATTRS_TO_PRESERVE:
            raise ToolAccessError(f"refusing to replace a file with unsupported extended attribute {name!r}")
        try:
            value = os.getxattr(fd, name)
        except (OSError, TypeError) as error:
            raise ToolAccessError(f"cannot preserve workspace file attribute {name!r}") from error
        total += len(value)
        if total > MAX_WORKSPACE_XATTR_BYTES:
            raise ToolAccessError("workspace file extended attributes exceed the replacement limit")
        captured[name] = value
    return captured


def _atomic_replace_workspace_file(
    ctx: ToolContext,
    path: Path,
    raw: bytes,
    *,
    create_parents: bool,
    expected: os.stat_result | None = None,
    check_expected: bool = False,
) -> None:
    """Stage complete bytes beside the target, then atomically publish them.

    Parent directories stay pinned by descriptor. Existing targets must remain
    the same singly-linked regular file observed before staging; a detected path
    swap or concurrent edit refuses the replacement. New files are linked into
    place with no-overwrite semantics so a concurrent creator is never silently lost.
    """
    with _workspace_parent_fd(ctx, path, create_parents=create_parents) as (parent_fd, name):
        observed = expected if check_expected else _workspace_target_stat(parent_fd, name)
        source_fd = -1
        attributes: dict[str, bytes] = {}
        if observed is not None:
            if not stat.S_ISREG(observed.st_mode):
                raise ToolAccessError("workspace writes require a regular file")
            if observed.st_nlink > 1:
                raise ToolAccessError("refusing to write a multiply-linked workspace file")
            if (observed.st_mode & 0o222) == 0:
                raise ToolAccessError("refusing to replace a read-only workspace file")
            try:
                flags = os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                try:
                    source_fd = os.open(name, os.O_RDONLY | flags, dir_fd=parent_fd)
                except PermissionError:
                    # A write-only file may still be replaceable; opening it for
                    # writing lets us inspect its metadata without reading content.
                    source_fd = os.open(name, os.O_WRONLY | flags, dir_fd=parent_fd)
                source_metadata = os.fstat(source_fd)
                if _file_version(source_metadata) != _file_version(observed):
                    raise ToolAccessError("workspace target changed while opening it for replacement")
                observed = source_metadata
                attributes = _workspace_xattrs(source_fd)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    if source_fd >= 0:
                        os.close(source_fd)
                        source_fd = -1
                    raise ToolAccessError("workspace target changed to a symlink during replacement") from error
                if source_fd >= 0:
                    os.close(source_fd)
                    source_fd = -1
                raise
            except BaseException:
                if source_fd >= 0:
                    os.close(source_fd)
                    source_fd = -1
                raise

        temporary = ""
        temporary_fd = -1
        try:
            for _ in range(16):
                candidate = f".northstar-write-{secrets.token_hex(16)}"
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0),
                        0o666,
                        dir_fd=parent_fd,
                    )
                    temporary = candidate
                    break
                except FileExistsError:
                    continue
            else:
                raise ToolAccessError("could not allocate a unique workspace staging file")

            if observed is not None:
                temporary_metadata = os.fstat(temporary_fd)
                if (temporary_metadata.st_uid, temporary_metadata.st_gid) != (observed.st_uid, observed.st_gid):
                    try:
                        os.fchown(temporary_fd, observed.st_uid, observed.st_gid)
                    except OSError as error:
                        raise ToolAccessError("cannot preserve workspace file ownership during replacement") from error
                if attributes:
                    if not callable(getattr(os, "setxattr", None)):
                        raise ToolAccessError("this host cannot preserve workspace file attributes safely")
                    try:
                        for attribute, value in attributes.items():
                            os.setxattr(temporary_fd, attribute, value)
                    except (OSError, TypeError) as error:
                        raise ToolAccessError("cannot preserve workspace file extended attributes") from error
                # Preserve ordinary read/write/execute bits, but do not carry
                # setuid/setgid bits onto newly written content.
                os.fchmod(temporary_fd, stat.S_IMODE(observed.st_mode) & 0o777)

            _write_fd(temporary_fd, raw)
            os.fsync(temporary_fd)
            staged = os.fstat(temporary_fd)
            named_staging = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
            if (staged.st_dev, staged.st_ino) != (named_staging.st_dev, named_staging.st_ino):
                raise ToolAccessError("workspace staging file changed during write")

            current = _workspace_target_stat(parent_fd, name)
            if observed is None:
                if current is not None:
                    raise ToolAccessError("workspace target appeared during write; refusing to overwrite it")
                # link() fails atomically if another writer creates the target
                # after the check above; both names are in the pinned directory.
                if (
                    os.link not in os.supports_dir_fd
                    or os.link not in os.supports_follow_symlinks
                ):
                    raise ToolAccessError("this host lacks safe no-overwrite workspace creation")
                os.link(
                    temporary,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(temporary, dir_fd=parent_fd)
                temporary = ""
            else:
                if current is None or _file_version(current) != _file_version(observed):
                    raise ToolAccessError("workspace target changed during write; refusing to discard the newer file")
                os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                temporary = ""
            os.fsync(parent_fd)
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if source_fd >= 0:
                os.close(source_fd)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass


def _write_fd(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("workspace write made no progress")
        view = view[written:]


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

_OBJECT_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}


def _schema(properties: Mapping[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    # Built-in tool contracts are closed by default. Dynamic maps (for example
    # Shell env vars or Fetch headers) must opt in through their property schema.
    payload: dict[str, Any] = {
        "type": "object",
        "properties": dict(properties),
        "additionalProperties": False,
    }
    if required:
        payload["required"] = list(required)
    return payload


def read_file(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Read at most ``limits.max_read_bytes`` of a workspace file."""
    requested = payload.get("path")
    path = ctx.resolve(requested, must_exist=True)
    limit = int(payload.get("max_bytes") or ctx.limits.max_read_bytes)
    limit = max(1, min(limit, ctx.limits.max_read_bytes))
    pins = ctx.service("skill_digests") or {}
    pin_name = ""
    if isinstance(requested, str) and ctx.sandbox is not None and isinstance(pins, Mapping):
        lexical = Path(requested)
        if not lexical.is_absolute():
            lexical = ctx.sandbox.root_real / lexical
        lexical = Path(os.path.normpath(str(lexical)))
        try:
            pin_name = lexical.relative_to(ctx.sandbox.root_real).as_posix()
        except ValueError:
            pass
    expected_digest = pins.get(pin_name) if pin_name else None
    pinned_limit = None
    if expected_digest is not None:
        from skills import MAX_SKILL_FILE_BYTES
        pinned_limit = MAX_SKILL_FILE_BYTES
    read_limit = pinned_limit if pinned_limit is not None else limit
    chunks: list[bytes] = []
    total = 0
    try:
        with _open_workspace_file(ctx, path, os.O_RDONLY) as fd:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                return ToolResult.error(f"not a file: {payload.get('path')}")
            if metadata.st_nlink > 1:
                return ToolResult.error("refusing to read a multiply-linked workspace file")
            size = metadata.st_size
            while total <= read_limit:
                chunk = os.read(fd, min(65536, read_limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except (OSError, ToolAccessError) as error:
        detail = "pinned skill" if expected_digest is not None else "workspace file"
        return ToolResult.error(f"cannot safely read {detail}: {error}", skill_integrity="failed" if expected_digest is not None else "unverified")
    raw = b"".join(chunks)
    if expected_digest is not None:
        if total > read_limit or hashlib.sha256(raw).hexdigest() != expected_digest:
            return ToolResult.error(
                "skill changed after run setup; refusing unreviewed instructions",
                skill_integrity="failed",
            )
        skill_integrity = "verified"
        raw = raw[: limit + 1]
        size = total
    else:
        skill_integrity = "unverified"
    truncated = len(raw) > limit or size > limit
    text = raw[:limit].decode("utf-8", "replace")
    if "\x00" in text:
        return ToolResult(
            content=f"[binary file, {size} bytes: {ctx.relative(path)} - not shown]",
            data={"bytes": 0, "truncated": truncated, "binary": True, "skill_integrity": skill_integrity},
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
        data={
            "path": ctx.relative(path),
            "bytes": min(limit, size),
            "size": size,
            "truncated": truncated,
            "skill_integrity": skill_integrity,
        },
    )


def _is_memory_write_target(path: Path, ctx: ToolContext) -> bool:
    from memory import is_memory_write_path

    return is_memory_write_path(Path(ctx.relative(path)).parts)


def _memory_write_check(path: Path, content: str, ctx: ToolContext) -> tuple[Any | None, ToolResult | None]:
    """Apply memory poisoning and size gates to the active memory carve-out."""
    if not _is_memory_write_target(path, ctx):
        return None, None

    from memory import MAX_MEMORY_BYTES, MAX_MEMORY_CHARS
    from memory_integrity import MemoryIntegrityError, record_memory_bytes, verify_memory_bytes

    relative = ctx.relative(path)
    try:
        current = None
        try:
            with _open_workspace_file(ctx, path, os.O_RDONLY) as fd:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
                    return None, ToolResult.error(
                        "memory target is not a singly-linked regular file",
                        memory_write_verdict="block",
                        integrity="failed",
                    )
                if metadata.st_size > MAX_MEMORY_BYTES:
                    return None, ToolResult.error(
                        f"existing memory file exceeds the active memory limit ({MAX_MEMORY_BYTES} bytes)",
                        memory_write_verdict="block",
                        integrity="unchecked_oversize",
                    )
                chunks: list[bytes] = []
                while chunk := os.read(fd, 65536):
                    chunks.append(chunk)
                current = b"".join(chunks)
        except FileNotFoundError:
            pass
        verify_memory_bytes(ctx.sandbox.root_real, relative, current)
    except (MemoryIntegrityError, OSError, ToolAccessError) as error:
        return None, ToolResult.error(
            f"memory integrity check refused the write: {error}",
            memory_write_verdict="block",
            integrity="failed",
        )

    if len(content) > MAX_MEMORY_CHARS or len(content.encode("utf-8")) > MAX_MEMORY_BYTES:
        return None, ToolResult.error(
            f"memory write exceeds the active memory limit ({MAX_MEMORY_CHARS} chars / {MAX_MEMORY_BYTES} bytes)",
            memory_write_verdict="block",
        )

    from memory_safety import gate_memory_write

    decision = gate_memory_write(
        content,
        writer="agent",
        session_id=ctx.session_id,
        source="tool:memory-write",
    )
    rejected = _memory_write_error(decision)
    if rejected is not None:
        return decision, rejected
    try:
        # Stage the expected digest first. If the subsequent memory write fails
        # or is partial, the next read detects the mismatch and fails closed.
        record_memory_bytes(
            ctx.sandbox.root_real,
            relative,
            content.encode("utf-8"),
            provenance=decision.provenance,
        )
    except MemoryIntegrityError as error:
        return decision, ToolResult.error(
            f"memory integrity baseline could not be updated: {error}",
            memory_write_verdict="block",
            integrity="failed",
        )
    return decision, None


def _memory_write_error(decision: Any | None) -> ToolResult | None:
    if decision is None or decision.verdict == "allow":
        return None
    if decision.verdict == "quarantine":
        reason = "quarantine policy is enabled, but this runtime has no quarantine store; write refused"
    else:
        reason = "memory write blocked by the poisoning guard"
    return ToolResult.error(
        f"{reason}: {decision.reason}",
        memory_write_verdict=decision.verdict,
        memory_provenance=decision.provenance,
    )


def write_file(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Create or overwrite a workspace file."""
    path = ctx.resolve(payload.get("path"), for_write=True)
    content = payload.get("content", "")
    if not isinstance(content, str):
        return ToolResult.error("content must be a string")
    if _is_memory_write_target(path, ctx):
        from memory_integrity import MemoryIntegrityError, memory_write_lock

        try:
            with memory_write_lock(ctx.sandbox.root_real):
                return _write_file_resolved(path, content, payload, ctx)
        except MemoryIntegrityError as error:
            return ToolResult.error(
                f"memory write lock refused the write: {error}",
                memory_write_verdict="block",
                integrity="failed",
            )
    return _write_file_resolved(path, content, payload, ctx)


def _write_file_resolved(path: Path, content: str, payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Perform a write with any managed-memory transaction lock already held."""
    if payload.get("mode") == "append":
        existing = ""
        if path.is_file() and _is_memory_write_target(path, ctx):
            from memory import MAX_MEMORY_BYTES
            try:
                with _open_workspace_file(ctx, path, os.O_RDONLY) as fd:
                    metadata = os.fstat(fd)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink > 1
                        or metadata.st_size > MAX_MEMORY_BYTES
                    ):
                        return ToolResult.error(
                            f"existing memory file exceeds the active memory limit ({MAX_MEMORY_BYTES} bytes)",
                            memory_write_verdict="block",
                        )
                    chunks: list[bytes] = []
                    total = 0
                    while total <= MAX_MEMORY_BYTES:
                        chunk = os.read(fd, min(65536, MAX_MEMORY_BYTES + 1 - total))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > MAX_MEMORY_BYTES:
                            break
                    existing = b"".join(chunks).decode("utf-8", "replace")
            except (OSError, ToolAccessError) as error:
                return ToolResult.error(f"cannot safely read existing memory: {error}", memory_write_verdict="block")
        decision, rejected = _memory_write_check(path, existing + content, ctx)
        if rejected is not None:
            return rejected
        try:
            _write_workspace_file(ctx, path, content, append=True)
        except (OSError, ToolAccessError) as error:
            return ToolResult.error(f"cannot safely append workspace file: {error}")
        data = {"path": ctx.relative(path), "bytes": len(content)}
        if decision is not None:
            data["memory_provenance"] = decision.provenance
        return ToolResult(content=f"appended {len(content)} chars to {ctx.relative(path)}", data=data)
    created = not path.exists()
    decision, rejected = _memory_write_check(path, content, ctx)
    if rejected is not None:
        return rejected
    try:
        _write_workspace_file(ctx, path, content)
    except (OSError, ToolAccessError) as error:
        return ToolResult.error(f"cannot safely write workspace file: {error}")
    data = {"path": ctx.relative(path), "bytes": len(content), "created": created}
    if decision is not None:
        data["memory_provenance"] = decision.provenance
    return ToolResult(
        content=f"wrote {len(content)} chars to {ctx.relative(path)}",
        data=data,
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
    if _is_memory_write_target(path, ctx):
        from memory_integrity import MemoryIntegrityError, memory_write_lock

        try:
            with memory_write_lock(ctx.sandbox.root_real):
                return _edit_file_resolved(path, old, new, payload, ctx)
        except MemoryIntegrityError as error:
            return ToolResult.error(
                f"memory write lock refused the edit: {error}",
                memory_write_verdict="block",
                integrity="failed",
            )
    return _edit_file_resolved(path, old, new, payload, ctx)


def _edit_file_resolved(
    path: Path,
    old: str,
    new: str,
    payload: dict[str, Any],
    ctx: ToolContext,
) -> ToolResult:
    """Perform an edit with any managed-memory transaction lock already held."""
    try:
        with _open_workspace_file(ctx, path, os.O_RDONLY) as fd:
            metadata_before = os.fstat(fd)
            if not stat.S_ISREG(metadata_before.st_mode):
                return ToolResult.error(f"not a file: {ctx.relative(path)}")
            if metadata_before.st_nlink > 1:
                return ToolResult.error("refusing to edit a multiply-linked workspace file")
            chunks: list[bytes] = []
            while chunk := os.read(fd, 65536):
                chunks.append(chunk)
            metadata = os.fstat(fd)
            if _file_version(metadata_before) != _file_version(metadata):
                return ToolResult.error("workspace file changed while it was being read; retry the edit")
            text = b"".join(chunks).decode("utf-8", "replace")
            count = text.count(old)
            if count == 0:
                return ToolResult.error(f"old_string not found in {ctx.relative(path)}")
            if count > 1 and not payload.get("replace_all", False):
                return ToolResult.error(
                    f"old_string matches {count} places in {ctx.relative(path)}; make it unique or pass replace_all=true"
                )
            updated = text.replace(old, new) if payload.get("replace_all") else text.replace(old, new, 1)
            decision, rejected = _memory_write_check(path, updated, ctx)
            if rejected is not None:
                return rejected
            _atomic_replace_workspace_file(
                ctx,
                path,
                updated.encode("utf-8"),
                create_parents=False,
                expected=metadata,
                check_expected=True,
            )
    except (OSError, ToolAccessError) as error:
        return ToolResult.error(f"cannot safely edit workspace file: {error}")
    data = {"path": ctx.relative(path), "matches": count}
    if decision is not None:
        data["memory_provenance"] = decision.provenance
    return ToolResult(
        content=f"edited {ctx.relative(path)} ({count} match(es), {1 if not payload.get('replace_all') else count} replaced)",
        data=data,
    )


def list_dir(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """List up to ``limits.max_list_entries`` entries of a workspace directory."""
    raw = payload.get("path", ".")
    path = ctx.resolve(raw if raw is not None else ".", must_exist=True)
    cap = ctx.limits.max_list_entries
    limit = int(payload.get("limit") or cap)
    limit = max(1, min(limit, cap))
    entries: list[dict[str, Any]] = []
    truncated = False
    try:
        with _open_workspace_directory(ctx, path) as directory_fd:
            metadata = os.fstat(directory_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                return ToolResult.error(f"not a directory: {raw}")
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    child = path / entry.name
                    if ctx.sandbox is not None and not ctx.sandbox.memory_path_allowed(child):
                        continue
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
    except (OSError, ToolAccessError) as error:
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
    collection_truncated = False
    collection_truncation_reason = ""
    targets: list[Path] = []
    if root.is_file():
        targets = [root]
    elif root.is_dir():
        pending = [root]
        visited_entries = 0
        while pending:
            current = pending.pop()
            children: list[os.DirEntry[str]] = []
            try:
                with os.scandir(current) as scan:
                    for entry in scan:
                        if visited_entries + len(children) >= MAX_GREP_TREE_ENTRIES:
                            collection_truncated = True
                            collection_truncation_reason = f"workspace tree entry budget of {MAX_GREP_TREE_ENTRIES}"
                            break
                        children.append(entry)
            except OSError:
                continue
            visited_entries += len(children)
            children.sort(key=lambda entry: entry.name)
            directories: list[Path] = []
            for entry in children:
                try:
                    child_path = Path(entry.path)
                    if ctx.sandbox is not None and not ctx.sandbox.memory_path_allowed(child_path):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in {".git", "__pycache__", "node_modules"}:
                            directories.append(child_path)
                    else:
                        targets.append(child_path)
                        if len(targets) >= ctx.limits.max_grep_files:
                            collection_truncated = True
                            collection_truncation_reason = f"file scan limit of {ctx.limits.max_grep_files}"
                            break
                except OSError:
                    continue
            if collection_truncated:
                break
            pending.extend(reversed(directories))
            if visited_entries >= MAX_GREP_TREE_ENTRIES and pending:
                collection_truncated = True
                collection_truncation_reason = f"workspace tree entry budget of {MAX_GREP_TREE_ENTRIES}"
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
            with _open_workspace_file(ctx, target, os.O_RDONLY) as fd:
                stat_result = os.fstat(fd)
                if (
                    not stat.S_ISREG(stat_result.st_mode)
                    or stat_result.st_nlink > 1
                    or stat_result.st_size > ctx.limits.max_grep_file_bytes
                ):
                    continue
                raw = os.read(fd, ctx.limits.max_grep_file_bytes)
        except (OSError, ToolAccessError):
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
    if collection_truncated:
        truncated = True
    body = "\n".join(matches) if matches else "no matches"
    if truncated:
        if collection_truncation_reason:
            body += f"\n[truncated at {collection_truncation_reason}]"
        else:
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


BUILTIN_TOOLS: tuple[str, ...] = (
    "Read",
    "Write",
    "Edit",
    "LS",
    "Grep",
    "DescribeTools",
    "Shell",
)


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
    # Shell is always registered so policy can name it; the permission gate keeps
    # it denied under `default` until --allow-tool Shell. Execution goes through
    # tools.os_sandbox (bwrap when usable, else scrubbed process).
    from tools.shell import shell_tool_spec

    registry.register(shell_tool_spec())
    return registry


def build_code_registry(include_describe: bool = True) -> ToolRegistry:
    """Default tools plus the structured programming profile.

    The generic ``run`` and ``agent`` surfaces keep their stable seven-tool
    kernel.  ``code`` opts into repository-specific capabilities explicitly,
    which also makes policy files and audit logs able to distinguish the two
    product profiles.
    """
    from tools.code import code_tool_specs

    registry = build_default_registry(include_describe=include_describe)
    for spec in code_tool_specs():
        registry.register(spec)
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
    "ToolWriteDenied",
    "ToolContext",
    "ToolInputError",
    "ToolKind",
    "ToolLimits",
    "ToolRegistry",
    "ToolResult",
    "ToolSandbox",
    "ToolSpec",
    "build_code_registry",
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

# Submodules used by doctor / CLI / tests (explicit re-exports keep import paths stable).
# os_sandbox and shell are part of the public tools surface for the product path.
