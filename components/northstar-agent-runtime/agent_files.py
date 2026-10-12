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

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Iterable, Mapping

from agents import READ_ONLY_TOOLS, AgentDefinition, AgentRegistry
from frontmatter import FrontmatterError, parse_frontmatter
from loop import DEFAULT_MAX_TOOL_CALLS, DEFAULT_MAX_TURNS

AGENTS_DIRECTORY = ".northstar/agents"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_MAX_DESCRIPTION_CHARS = 600
_MAX_PROMPT_CHARS = 16_000
MAX_AGENT_FILES = 40
MAX_AGENT_DIRECTORY_ENTRIES = 256
MAX_AGENT_FILE_BYTES = 256 * 1024

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
    reviewed_digests: Mapping[str, str] | None = None,
) -> tuple[AgentDefinition, ...]:
    """Compile every ``.northstar/agents/*.md`` into an AgentDefinition.

    ``extra_paths`` accepts directories or single files from an installed plugin bundle.
    They are parsed by the same function and confined by the same rule, so a plugin's agent
    file gets exactly the privileges a repository's own agent file has - no more.
    """
    root = Path(workspace).resolve()
    directory = root / AGENTS_DIRECTORY
    known = frozenset(known_tools or ())
    candidates: list[tuple[Path, bool]] = []
    if directory.is_dir():
        candidates.extend((path, False) for path in _agent_markdown_files(directory))
    if len(candidates) > MAX_AGENT_FILES:
        raise AgentFileError(f"workspace agent set exceeds the {MAX_AGENT_FILES}-file limit")
    for extra in extra_paths:
        path = Path(extra)
        if path.is_dir():
            candidates.extend((item, True) for item in _agent_markdown_files(path))
        elif path.is_file():
            candidates.append((path, True))
        else:
            raise AgentFileError(f"plugin agent path {path} is not a regular file or directory")
        if len(candidates) > MAX_AGENT_FILES:
            raise AgentFileError(f"workspace agent set exceeds the {MAX_AGENT_FILES}-file limit")
    definitions: list[AgentDefinition] = []
    for entry, plugin_owned in candidates:
        resolved = entry.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise AgentFileError(
                f"agent file {entry} resolves outside the workspace root {root}; "
                "refusing to follow the symlink"
            )
        if entry.is_symlink():
            raise AgentFileError(f"agent file {entry} is a symlink; refusing to follow it")
        relative = resolved.relative_to(root).as_posix()
        expected = (reviewed_digests or {}).get(relative)
        if plugin_owned and reviewed_digests is not None and not expected:
            raise AgentFileError(f"plugin agent {entry} has no reviewed content digest")
        definitions.append(_parse_agent_file(entry, known_tools=known, expected_digest=expected))
    return tuple(definitions)


def _agent_markdown_files(directory: Path) -> tuple[Path, ...]:
    """Collect direct Markdown definitions without glob materializing an unbounded tree."""
    if directory.is_symlink():
        raise AgentFileError(f"agent directory {directory} is a symlink; refusing to follow it")
    candidates: list[Path] = []
    try:
        with os.scandir(directory) as scan:
            entries = []
            for entry in scan:
                entries.append(entry)
                if len(entries) > MAX_AGENT_DIRECTORY_ENTRIES:
                    raise AgentFileError(
                        f"agent directory {directory} exceeds the {MAX_AGENT_DIRECTORY_ENTRIES}-entry scan limit"
                    )
    except OSError as error:
        raise AgentFileError(f"cannot scan agent directory {directory}: {error}") from error
    for entry in sorted(entries, key=lambda item: item.name):
        if not entry.name.endswith(".md"):
            continue
        try:
            if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                candidates.append(Path(entry.path))
        except OSError as error:
            raise AgentFileError(f"cannot inspect agent file {entry.path}: {error}") from error
    return tuple(candidates)


def _read_agent_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise AgentFileError(f"{path}: cannot open agent file: {error}") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
            raise AgentFileError(f"{path}: agent file must be a regular single-link file")
        if metadata.st_size > MAX_AGENT_FILE_BYTES:
            raise AgentFileError(f"{path}: agent file exceeds the {MAX_AGENT_FILE_BYTES}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(64 * 1024, MAX_AGENT_FILE_BYTES + 1 - total)):
            total += len(chunk)
            if total > MAX_AGENT_FILE_BYTES:
                raise AgentFileError(f"{path}: agent file grew beyond the {MAX_AGENT_FILE_BYTES}-byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def register_workspace_agents(
    registry: AgentRegistry,
    workspace: str | Path,
    *,
    known_tools: Iterable[str] | None = None,
    extra_paths: Iterable[str | Path] = (),
    reviewed_digests: Mapping[str, str] | None = None,
) -> tuple[AgentDefinition, ...]:
    """Discover repository agents and register them; collisions are errors.

    The collision rule is what makes ``extra_paths`` safe: a plugin may add a subagent, and
    may not take over a name a built-in or the repository already uses.
    """
    definitions = discover_agent_files(
        workspace, known_tools=known_tools, extra_paths=extra_paths, reviewed_digests=reviewed_digests
    )
    for definition in definitions:
        try:
            registry.register(definition, replace_existing=False)
        except ValueError as error:
            raise AgentFileError(
                f"{definition.name!r}: {error} - repository agents may not shadow "
                "a built-in agent or another repository agent"
            ) from error
    return definitions


def _parse_agent_file(
    path: Path, *, known_tools: frozenset[str], expected_digest: str | None = None
) -> AgentDefinition:
    raw = _read_agent_file(path)
    if expected_digest is not None and hashlib.sha256(raw).hexdigest() != expected_digest:
        raise AgentFileError(f"{path}: plugin agent changed since bundle review; refusing definition")
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
