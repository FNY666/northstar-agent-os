"""Workspace-scoped agent memory (P4): durable notes inside the run boundary.

Design (blueprint C7 — **reject global MEMORY**):

* Lives only under the workspace: ``.northstar/memory/MEMORY.md`` by default.
* Injected into the system prompt as a clearly delimited block with a content
  digest so an audit reader can see *which* memory a run started from.
* Size-capped (never unbounded context growth).
* Opt-out: ``--no-memory`` / ``memory=false`` in policy.
* **Writes** go through the ordinary ``Write`` / ``Edit`` tools and the same
  permission gate. The tool sandbox carves ``.northstar/memory/`` as the sole
  writable subtree under ``.northstar`` so the agent can update its notes
  without being allowed to rewrite policy, agents, or skills.
* No user-home path, no cross-workspace store, no silent merge from outside.

This module is pure discovery + prompt composition. It never creates the
memory file on its own during a run (a missing file means "no memory yet").
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Directory under the workspace that holds agent memory (writable carve-out).
MEMORY_DIRECTORY = ".northstar/memory"

#: Default file name inside the memory directory.
MEMORY_FILE_NAME = "MEMORY.md"

#: Closed ceilings — a memory file cannot grow a run's prompt without bound.
MAX_MEMORY_CHARS = 12_000
MAX_MEMORY_BYTES = 32 * 1024

_MARKERS = (
    "\n\n== Workspace memory ({name}, digest={digest}) ==\n",
    "\n== End of workspace memory ==",
)


class MemoryError(ValueError):
    """A memory path the runtime refuses. Operator-facing."""


@dataclass(frozen=True)
class WorkspaceMemory:
    """Discovered memory, ready to append to the system prompt."""

    name: str
    text: str
    path: Path
    digest: str
    truncated: bool = False
    relative: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.relative or str(self.path),
            "digest": self.digest,
            "chars": len(self.text),
            "truncated": self.truncated,
        }


def memory_directory(workspace: str | Path) -> Path:
    return Path(workspace) / MEMORY_DIRECTORY


def default_memory_path(workspace: str | Path) -> Path:
    return memory_directory(workspace) / MEMORY_FILE_NAME


def is_memory_write_path(relative_parts: tuple[str, ...]) -> bool:
    """True when ``relative_parts`` is under the writable memory carve-out.

    Used by :class:`tools.ToolSandbox` so ``.northstar/memory/…`` is editable
    while every other ``.northstar`` path stays write-protected.
    """
    head = Path(MEMORY_DIRECTORY).parts  # ('.northstar', 'memory')
    if len(relative_parts) < len(head):
        return False
    return relative_parts[: len(head)] == head


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def discover_memory(
    workspace: str | Path,
    *,
    configured: str | bool | None = None,
    explicit: str | Path | None = None,
) -> WorkspaceMemory | None:
    """Load workspace memory, or ``None`` when absent / disabled.

    ``configured``:
      * ``None`` / ``True`` → default ``.northstar/memory/MEMORY.md``
      * ``False`` → disabled
      * ``str`` → path relative to the workspace root (must stay inside it)

    ``explicit`` is a CLI ``--memory-file`` override (must resolve inside the
    workspace; symlink escape is refused).
    """
    root = Path(workspace).resolve()
    if configured is False and explicit is None:
        return None

    if explicit is not None:
        candidate = Path(explicit)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = Path(os.path.realpath(str(candidate)))
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise MemoryError(
                f"--memory-file {explicit} resolves outside the workspace root {root}; "
                "memory must live inside the workspace (no global MEMORY)"
            ) from error
        if not resolved.is_file():
            raise MemoryError(f"--memory-file {explicit} does not exist")
        return _read_memory(resolved, root, display_name=Path(explicit).name)

    if configured is False:
        return None

    if isinstance(configured, str) and configured.strip():
        name = configured.strip()
        if name.startswith("/") or ".." in Path(name).parts or any(ch in name for ch in "\\\x00"):
            raise MemoryError(
                f"memory path {name!r} must be a plain relative path inside the workspace"
            )
        candidate = root / name
    else:
        candidate = default_memory_path(root)

    resolved = Path(os.path.realpath(str(candidate)))
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise MemoryError(
            f"memory path {candidate} resolves outside the workspace root {root}; "
            "refusing to follow the symlink (no global MEMORY)"
        ) from error
    if not candidate.is_file():
        return None
    return _read_memory(resolved, root, display_name=candidate.name)


def _read_memory(path: Path, root: Path, *, display_name: str) -> WorkspaceMemory:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise MemoryError(f"{path}: cannot read memory: {error}") from error
    if len(raw) > MAX_MEMORY_BYTES:
        raw = raw[:MAX_MEMORY_BYTES]
        truncated_bytes = True
    else:
        truncated_bytes = False
    text = raw.decode("utf-8", errors="replace")
    truncated = truncated_bytes or len(text) > MAX_MEMORY_CHARS
    if len(text) > MAX_MEMORY_CHARS:
        text = text[:MAX_MEMORY_CHARS]
    digest = digest_text(text)
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = display_name
    return WorkspaceMemory(
        name=display_name,
        text=text,
        path=path,
        digest=digest,
        truncated=truncated,
        relative=relative,
    )


def append_memory(base_prompt: str, memory: WorkspaceMemory) -> str:
    """Append clearly delimited memory content to a system prompt."""
    start = _MARKERS[0].format(name=memory.name, digest=memory.digest[:12])
    end = _MARKERS[1]
    body = memory.text if not memory.truncated else memory.text + "\n[truncated]"
    note = (
        f"(workspace-scoped only; update via Write/Edit on '{memory.relative}' — "
        "never a global MEMORY store)\n"
    )
    return f"{base_prompt}{start}{note}{body}{end}"


def ensure_memory_dir(workspace: str | Path) -> Path:
    """Create the memory directory (mode 0700) so a first Write has a home.

    Called only when an operator or scaffold asks — never silently mid-run.
    """
    directory = memory_directory(workspace)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


__all__ = [
    "MEMORY_DIRECTORY",
    "MEMORY_FILE_NAME",
    "MAX_MEMORY_BYTES",
    "MAX_MEMORY_CHARS",
    "MemoryError",
    "WorkspaceMemory",
    "append_memory",
    "default_memory_path",
    "digest_text",
    "discover_memory",
    "ensure_memory_dir",
    "is_memory_write_path",
    "memory_directory",
]
