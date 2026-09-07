"""Workspace policy file (``.northstar/config.toml``) and project context (``AGENTS.md``).

Two complementary, repository-scoped inputs, both discovered under the workspace
root and both *only ever able to tighten* what a run may do:

- The policy file pins defaults for a run (permission mode, denials, ceilings,
  halt-on-denial, default agent, project-context file). It is parsed with the
  standard library ``tomllib`` (Python 3.11+) or the optional ``tomli`` shim on
  3.10. A file that is unreadable, contains an unknown key, or would *loosen* a
  guardrail (``bypassPermissions``, ``allow_tools`` naming a mutating tool, a
  ceiling above the built-in default, ...) is a configuration error: the run
  refuses to start rather than silently ignoring operator policy.
- The project context (``AGENTS.md`` by default, or the name configured in the
  policy file, or an explicit ``--context-file``) is appended to the system
  prompt as clearly delimited developer-authored content. Discovery only ever
  resolves *inside* the workspace root; a symlink that points out of the
  workspace is rejected, never followed.

Both features are opt-out at the command line (``--no-policy-file``,
``--no-project-context``) but on by default once the files exist: a repository
that ships a policy file is declaring that policy for every run inside it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ImportError as error:  # pragma: no cover - depends on the host
        raise ImportError(
            "reading .northstar/config.toml needs Python 3.11+ or the 'tomli' package "
            "(pip install tomli)"
        ) from error

POLICY_DIRECTORY = ".northstar"
POLICY_FILE_NAME = "config.toml"
DEFAULT_PROJECT_CONTEXT_FILE = "AGENTS.md"

# Canonical policy-document identity, mirrored from the run contract's
# ``policy`` module (the runtime is deliberately dependency-free; the test
# suite pins both sides to the same strings).
POLICY_SCHEMA_VERSION = "northstar.policy.v1"
SUPPORTED_POLICY_SCHEMA_VERSIONS: tuple[str, ...] = (POLICY_SCHEMA_VERSION,)
# Revision ids mirror the contract id rule (_valid_id): no whitespace, no
# slashes, at most 128 chars — they are audit correlation keys.
MAX_REVISION_CHARS = 128

# Project instructions are developer-authored content appended to the system
# prompt. Cap it so a workspace file cannot grow a run's context without bound.
CONTEXT_MAX_CHARS = 64_000

# Tighten-only ceilings, mirrored from loop.py's built-in defaults. The test
# suite asserts these stay in sync with loop.DEFAULT_*.
DEFAULT_MAX_TURNS = 25
DEFAULT_MAX_TOOL_CALLS = 50
DEFAULT_COMPACTION_THRESHOLD_TOKENS = 60_000
# Auto-approval of a mutating tool is an operator-at-runtime decision, never a
# repository file decision.
MUTATING_TOOLS = ("Write", "Edit")
# A sidecar tool that may not even be registered yet; denying it in a policy
# file is forward-looking and harmless.
ALWAYS_KNOWN_TOOLS = ("CodexReadOnly",)

_ALLOWED_KEYS = frozenset({
    "schema_version",
    "revision",
    "permission_mode",
    "read_only",
    "deny_tools",
    "allow_tools",
    "max_turns",
    "max_tool_calls",
    "max_budget_usd",
    "halt_on_denial",
    "agent",
    "compaction_threshold_tokens",
    "project_context",
})
_ALLOWED_MODES = frozenset({"default", "plan"})
_CONTEXT_MARKERS = (
    "\n\n== Project instructions ({name}) ==\n",
    "\n== End of project instructions ==",
)


class PolicyFileError(ValueError):
    """The workspace policy file is unusable. Message is operator-facing."""


@dataclass(frozen=True)
class PolicyFile:
    """Validated contents of ``.northstar/config.toml``.

    Every field is optional; ``None``/empty means "no opinion from the file".
    Values that passed validation can only tighten relative to built-ins.
    """

    source: Path
    schema_version: str = POLICY_SCHEMA_VERSION  # northstar.policy.v1 (canonical identity)
    revision: str | None = None                 # audit correlation key for this file revision
    permission_mode: str | None = None          # "default" | "plan"
    read_only: bool | None = None               # True only ever; False is a no-op
    deny_tools: tuple[str, ...] = ()
    allow_tools: tuple[str, ...] = ()           # always empty: approvals are CLI-only
    max_turns: int | None = None                # <= DEFAULT_MAX_TURNS
    max_tool_calls: int | None = None           # <= DEFAULT_MAX_TOOL_CALLS
    max_budget_usd: float | None = None         # > 0 (the default is unlimited)
    halt_on_denial: bool | None = None
    agent: str | None = None                    # a known built-in agent name
    compaction_threshold_tokens: int | None = None  # <= DEFAULT_COMPACTION_THRESHOLD_TOKENS
    project_context: str | bool | None = None   # file name, False to disable, None = default

    @property
    def project_context_setting(self) -> str | bool:
        return DEFAULT_PROJECT_CONTEXT_FILE if self.project_context is None else self.project_context

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "schema_version": self.schema_version,
            "revision": self.revision,
            "permission_mode": self.permission_mode,
            "read_only": self.read_only,
            "deny_tools": list(self.deny_tools),
            "allow_tools": list(self.allow_tools),
            "max_turns": self.max_turns,
            "max_tool_calls": self.max_tool_calls,
            "max_budget_usd": self.max_budget_usd,
            "halt_on_denial": self.halt_on_denial,
            "agent": self.agent,
            "compaction_threshold_tokens": self.compaction_threshold_tokens,
            "project_context": self.project_context_setting,
        }


def policy_file_path(workspace: str | Path) -> Path:
    return Path(workspace) / POLICY_DIRECTORY / POLICY_FILE_NAME


def load_policy_file(
    workspace: str | Path,
    *,
    known_tools: Iterable[str] | None = None,
    known_agents: Iterable[str] | None = None,
) -> PolicyFile | None:
    """Load and validate the workspace policy file; ``None`` when absent.

    Raises :class:`PolicyFileError` with an operator-facing message on any
    unreadable, unparseable, unknown-key, type-error, or loosen-only violation.
    """
    path = policy_file_path(workspace)
    if not path.is_file():
        return None
    try:
        raw = _toml.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyFileError(f"{path}: cannot read policy file: {error}") from error
    except Exception as error:  # tomllib.TOMLDecodeError / tomli
        raise PolicyFileError(f"{path}: invalid TOML: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyFileError(f"{path}: the policy file must be a TOML table")

    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise PolicyFileError(
            f"{path}: unknown key(s) {', '.join(unknown)} - allowed: {', '.join(sorted(_ALLOWED_KEYS))}"
        )

    def fail(message: str) -> None:
        raise PolicyFileError(f"{path}: {message}")

    # Document identity: a supported schema_version and an optional revision.
    # An unsupported (future) schema must fail closed instead of being read
    # with today's looser semantics.
    schema_version = raw.get("schema_version")
    if schema_version is None:
        schema_version = POLICY_SCHEMA_VERSION
    if not isinstance(schema_version, str) or schema_version not in SUPPORTED_POLICY_SCHEMA_VERSIONS:
        supported = ", ".join(SUPPORTED_POLICY_SCHEMA_VERSIONS)
        fail(f"unsupported policy schema_version {schema_version!r} - this runtime supports: {supported}")

    revision = raw.get("revision")
    if revision is not None:
        if not isinstance(revision, str) or not revision:
            fail("revision must be a non-empty string (e.g. '2026-09-07.r1')")
        if len(revision) > MAX_REVISION_CHARS:
            fail("revision is too long")
        if any(char.isspace() or char in "/\\" for char in revision):
            fail("revision must not contain whitespace, /, or \\ (it is an audit correlation key)")

    known_tools_set = set(known_tools or ()) | set(ALWAYS_KNOWN_TOOLS)
    known_agents_set = set(known_agents or ())

    mode = raw.get("permission_mode")
    if mode is not None:
        if not isinstance(mode, str) or mode not in _ALLOWED_MODES:
            fail(
                f"permission_mode must be 'default' or 'plan' (a policy file may only tighten; "
                f"pass --permission-mode acceptEdits|bypassPermissions on the command line for one run)"
            )
    read_only = raw.get("read_only")
    if read_only is not None and not isinstance(read_only, bool):
        fail("read_only must be a boolean")

    deny = raw.get("deny_tools", [])
    if not isinstance(deny, list) or not all(isinstance(name, str) for name in deny):
        fail("deny_tools must be an array of tool names")
    for name in deny:
        # mcp__-prefixed names are forward-looking (like CodexReadOnly): MCP
        # servers connect after policy validation, so their tool names cannot be
        # known here. A deny of a tool a server never exposes is a harmless no-op.
        if known_tools_set and name not in known_tools_set and not name.startswith("mcp__"):
            known = ", ".join(sorted(known_tools_set))
            fail(f"deny_tools lists unknown tool {name!r} - known tools: {known}")

    allow = raw.get("allow_tools", [])
    if allow is not None and len(allow) > 0:
        fail(
            "allow_tools is not allowed in a policy file: auto-approval is an operator-at-run "
            "decision (--allow-tool on the command line); a policy file may only deny"
        )

    def ceiling(key: str, default: int, *, allow_zero: bool = False) -> int | None:
        value = raw.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
            fail(f"{key} must be a positive integer")
        if not allow_zero and value == 0:
            fail(f"{key} must be a positive integer")
        if value > default:
            fail(f"{key} may only lower the built-in ceiling of {default} (a policy file may only tighten)")
        return value

    max_turns = ceiling("max_turns", DEFAULT_MAX_TURNS)
    max_tool_calls = ceiling("max_tool_calls", DEFAULT_MAX_TOOL_CALLS)
    compaction = ceiling("compaction_threshold_tokens", DEFAULT_COMPACTION_THRESHOLD_TOKENS, allow_zero=True)

    budget = raw.get("max_budget_usd")
    if budget is not None:
        if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0:
            fail("max_budget_usd must be a positive number (the built-in default is unlimited)")
        budget = float(budget)

    halt = raw.get("halt_on_denial")
    if halt is not None and not isinstance(halt, bool):
        fail("halt_on_denial must be a boolean")

    agent = raw.get("agent")
    if agent is not None:
        if not isinstance(agent, str) or not agent.strip():
            fail("agent must be a non-empty agent name")
        if known_agents_set and agent not in known_agents_set:
            known = ", ".join(sorted(known_agents_set))
            fail(f"agent names unknown agent {agent!r} - known agents: {known}")

    context = raw.get("project_context", DEFAULT_PROJECT_CONTEXT_FILE)
    if isinstance(context, bool):
        pass  # False disables discovery; True means the default file
    elif isinstance(context, str):
        if not context.strip() or context.strip() in {".", ".."} or "/" in context or "\\" in context:
            fail("project_context must be a plain file name inside the workspace root, or false to disable")
    else:
        fail("project_context must be a file name string or a boolean")

    return PolicyFile(
        source=path,
        schema_version=schema_version,
        revision=revision,
        permission_mode=mode,
        read_only=read_only,
        deny_tools=tuple(deny),
        allow_tools=(),
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        max_budget_usd=budget,
        halt_on_denial=halt,
        agent=agent,
        compaction_threshold_tokens=compaction,
        project_context=context if context is not DEFAULT_PROJECT_CONTEXT_FILE or "project_context" in raw else None,
    )


# -- project context (AGENTS.md) --------------------------------------------


@dataclass(frozen=True)
class ProjectContext:
    """A discovered project-instructions file, ready to append to the prompt."""

    name: str
    text: str
    path: Path
    truncated: bool = False


def discover_project_context(
    workspace: str | Path,
    *,
    configured: str | bool = DEFAULT_PROJECT_CONTEXT_FILE,
    explicit: str | Path | None = None,
) -> ProjectContext | None:
    """Find the project-instructions file to inject, or ``None``.

    ``configured`` comes from the policy file (a file name, or ``False`` to
    disable). ``explicit`` is a ``--context-file`` path: it must exist and must
    resolve inside the workspace root - a symlink pointing out of the workspace
    is rejected, never followed.
    """
    root = Path(workspace).resolve()
    if explicit is not None:
        candidate = Path(explicit)
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise PolicyFileError(
                f"--context-file {candidate} resolves outside the workspace root {root}; "
                "project context must live inside the workspace"
            )
        if not candidate.is_file():
            raise PolicyFileError(f"--context-file {candidate} does not exist")
        return _read_context(resolved, candidate.name)
    if configured is False:
        return None
    name = configured if isinstance(configured, str) else DEFAULT_PROJECT_CONTEXT_FILE
    candidate = root / name
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise PolicyFileError(
            f"project context {name} in the workspace resolves outside the workspace root {root}; "
            "refusing to follow the symlink"
        )
    if not candidate.is_file():
        return None
    return _read_context(resolved, name)


def _read_context(path: Path, name: str) -> ProjectContext:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PolicyFileError(f"{path}: cannot read project context: {error}") from error
    text = raw.decode("utf-8", errors="replace")
    truncated = len(text) > CONTEXT_MAX_CHARS
    if truncated:
        text = text[:CONTEXT_MAX_CHARS]
    return ProjectContext(name=name, text=text, path=path, truncated=truncated)


def append_project_context(base_prompt: str, context: ProjectContext) -> str:
    """Append clearly delimited developer-authored content to a system prompt."""
    start, end = (marker.format(name=context.name) for marker in _CONTEXT_MARKERS)
    body = context.text if not context.truncated else context.text + "\n[truncated]"
    return f"{base_prompt}{start}{body}{end}"
