"""Repository-defined subagents: ``.northstar/agents/*.md``.

A markdown file in that directory (frontmatter + prompt body) compiles into an
:class:`~agents.AgentDefinition` and joins the registry exactly like a built-in
subagent: usable with ``--agent``, delegatable through the ``Task`` tool under
the existing delegation gate, and listed by ``cli agents``.

The governance contract mirrors the policy file: a repository file may only
tighten.

- ``name`` must be a lowercase identifier that does not collide with a built-in
  agent (or another file);
- ``tools`` must name known tools only, and must stay non-empty;
- ``read_only`` filters the tool set down to read-only tools (never widens);
- ``permission_mode`` is limited to ``default`` / ``plan``; ceilings may only
  lower the runtime's built-in limits;
- anything unreadable, unknown, or loosening is an error (the CLI exits 64),
  never a silent ignore.

The markdown body becomes the agent's prompt.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from agents import READ_ONLY_TOOLS, AgentDefinition, AgentRegistry
from frontmatter import FrontmatterError, parse_frontmatter
from loop import DEFAULT_MAX_TOOL_CALLS, DEFAULT_MAX_TURNS

AGENTS_DIRECTORY = ".northstar/agents"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_MAX_DESCRIPTION_CHARS = 600
_MAX_PROMPT_CHARS = 16_000

_ALLOWED_KEYS = frozenset({
    "name",
    "description",
    "tools",
    "read_only",
    "permission_mode",
    "model",
    "max_turns",
    "max_tool_calls",
    "allow_delegation",
    "require_verdict",
})
_ALLOWED_MODES = frozenset({"default", "plan"})


class AgentFileError(ValueError):
    """A repository agent file is unusable. Message is operator-facing."""


def agents_directory(workspace: str | Path) -> Path:
    return Path(workspace) / AGENTS_DIRECTORY


def discover_agent_files(
    workspace: str | Path,
    *,
    known_tools: Iterable[str] | None = None,
    extra_paths: Iterable[str | Path] = (),
) -> tuple[AgentDefinition, ...]:
    """Compile every ``.northstar/agents/*.md`` into an AgentDefinition.

    ``extra_paths`` accepts directories or single files from an installed plugin bundle.
    They are parsed by the same function and confined by the same rule, so a plugin's agent
    file gets exactly the privileges a repository's own agent file has - no more.
    """
    root = Path(workspace).resolve()
    directory = root / AGENTS_DIRECTORY
    known = frozenset(known_tools or ())
    candidates: list[Path] = sorted(directory.glob("*.md")) if directory.is_dir() else []
    for extra in extra_paths:
        path = Path(extra)
        if path.is_dir():
            candidates.extend(sorted(path.glob("*.md")))
        elif path.is_file():
            candidates.append(path)
    definitions: list[AgentDefinition] = []
    for entry in candidates:
        resolved = entry.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise AgentFileError(
                f"agent file {entry} resolves outside the workspace root {root}; "
                "refusing to follow the symlink"
            )
        definitions.append(_parse_agent_file(entry, known_tools=known))
    return tuple(definitions)


def register_workspace_agents(
    registry: AgentRegistry,
    workspace: str | Path,
    *,
    known_tools: Iterable[str] | None = None,
    extra_paths: Iterable[str | Path] = (),
) -> tuple[AgentDefinition, ...]:
    """Discover repository agents and register them; collisions are errors.

    The collision rule is what makes ``extra_paths`` safe: a plugin may add a subagent, and
    may not take over a name a built-in or the repository already uses.
    """
    definitions = discover_agent_files(workspace, known_tools=known_tools, extra_paths=extra_paths)
    for definition in definitions:
        try:
            registry.register(definition, replace_existing=False)
        except ValueError as error:
            raise AgentFileError(
                f"{definition.name!r}: {error} - repository agents may not shadow "
                "a built-in agent or another repository agent"
            ) from error
    return definitions


def _parse_agent_file(path: Path, *, known_tools: frozenset[str]) -> AgentDefinition:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AgentFileError(f"{path}: cannot read agent file: {error}") from error
    try:
        fields, body = parse_frontmatter(raw.decode("utf-8", errors="replace"))
    except FrontmatterError as error:
        raise AgentFileError(f"{path}: {error}") from error
    if fields is None:
        raise AgentFileError(f"{path}: an agent file needs YAML frontmatter (name and description)")
    unknown = sorted(set(fields) - _ALLOWED_KEYS)
    if unknown:
        raise AgentFileError(
            f"{path}: unknown key(s) {', '.join(unknown)} - "
            f"allowed: {', '.join(sorted(_ALLOWED_KEYS))}"
        )

    def fail(message: str) -> None:
        raise AgentFileError(f"{path}: {message}")

    name = fields.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        fail(f"name must be a lowercase identifier matching {_NAME_RE.pattern!r}")
    description = fields.get("description", "")
    if not isinstance(description, str):
        fail("description must be a string")
    description = description.strip()[: _MAX_DESCRIPTION_CHARS]

    tools_raw = fields.get("tools")
    if not isinstance(tools_raw, list) or not tools_raw or not all(isinstance(t, str) for t in tools_raw):
        fail("tools must be a non-empty array of tool names")
    tools: list[str] = []
    for tool in tools_raw:
        if known_tools and tool not in known_tools:
            known = ", ".join(sorted(known_tools))
            fail(f"tools lists unknown tool {tool!r} - known tools: {known}")
        tools.append(tool)

    read_only = fields.get("read_only", False)
    if not isinstance(read_only, bool):
        fail("read_only must be a boolean")
    if read_only:
        tools = [tool for tool in tools if tool in READ_ONLY_TOOLS or tool == "CodexReadOnly"]
        if not tools:
            fail("read_only leaves the agent with no read-only tools to use")

    mode = fields.get("permission_mode", "default")
    if mode not in _ALLOWED_MODES:
        fail("permission_mode must be 'default' or 'plan' (a repository agent may only tighten)")

    model = fields.get("model", "")
    if not isinstance(model, str):
        fail("model must be a string")

    max_turns = fields.get("max_turns", 6)
    if isinstance(max_turns, bool) or not isinstance(max_turns, int) or not 1 <= max_turns <= DEFAULT_MAX_TURNS:
        fail(f"max_turns must be an integer between 1 and {DEFAULT_MAX_TURNS} (may only tighten)")
    max_tool_calls = fields.get("max_tool_calls", 12)
    if (
        isinstance(max_tool_calls, bool)
        or not isinstance(max_tool_calls, int)
        or not 1 <= max_tool_calls <= DEFAULT_MAX_TOOL_CALLS
    ):
        fail(f"max_tool_calls must be an integer between 1 and {DEFAULT_MAX_TOOL_CALLS} (may only tighten)")

    allow_delegation = fields.get("allow_delegation", False)
    if not isinstance(allow_delegation, bool):
        fail("allow_delegation must be a boolean")
    require_verdict = fields.get("require_verdict", False)
    if not isinstance(require_verdict, bool):
        fail("require_verdict must be a boolean")

    if not body:
        fail("the markdown body is the agent's prompt and must not be empty")
    if len(body) > _MAX_PROMPT_CHARS:
        body = body[: _MAX_PROMPT_CHARS] + "\n[prompt truncated]"

    return AgentDefinition(
        name=name,
        description=description,
        prompt=body,
        tools=tuple(tools),
        permission_mode=mode,
        model=model,
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        allow_delegation=allow_delegation,
        require_verdict=require_verdict,
        read_only_enforced=read_only,
    )
