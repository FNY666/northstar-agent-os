"""Tool discovery: registry with search, Simulated.

A registry of tools with metadata, searchable by name, description,
tags, and capabilities.  Case-insensitive substring matching with
relevance ranking.

What this IS: find the right tool for a task.

What this IS NOT:
* Not a remote service -- in-process registry.
* Search is substring-based, not semantic.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
TOOL_SYSTEM_01_VERSION = "tool-system-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-01.v1"


class ToolSystem01Error(Exception):
    """Fail-closed: bad input raises."""


@dataclass(frozen=True)
class ToolInfo:
    """Metadata for one tool."""

    name: str
    description: str
    tags: tuple = ()
    capabilities: tuple = ()


class ToolRegistry:
    """Registry of tools with search."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolInfo] = {}

    def register(self, info: ToolInfo) -> None:
        if not info.name or not isinstance(info.name, str):
            raise ToolSystem01Error("tool name required")
        self._tools[info.name] = info

    def get(self, name: str) -> ToolInfo:
        if name not in self._tools:
            raise ToolSystem01Error(f"unknown tool '{name}'")
        return self._tools[name]

    def search(self, query: str, limit: int = 10) -> List[ToolInfo]:
        """Search by name/description/tags.  Ranked by match count."""
        if not isinstance(query, str):
            raise ToolSystem01Error("query must be str")
        q = query.lower().strip()
        if not q:
            return []
        scored: List[tuple] = []
        for info in self._tools.values():
            score = 0
            if q in info.name.lower():
                score += 3
            if q in info.description.lower():
                score += 2
            for tag in info.tags:
                if q in str(tag).lower():
                    score += 1
                    break
            for cap in info.capabilities:
                if q in str(cap).lower():
                    score += 1
                    break
            if score > 0:
                scored.append((score, info))
        scored.sort(key=lambda x: (-x[0], x[1].name))
        return [info for _, info in scored[:limit]]

    def list_names(self) -> List[str]:
        return sorted(self._tools.keys())


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    r = ToolRegistry()
    r.register(ToolInfo("read_file", "Read a file", ("fs",), ("read",)))
    r.register(ToolInfo("write_file", "Write a file", ("fs",), ("write",)))
    r.register(ToolInfo("send_email", "Send email", ("net",), ("send",)))
    assert len(r.search("file")) == 2
    assert r.search("file")[0].name in ("read_file", "write_file")
    assert len(r.search("email")) == 1
    assert r.search("") == []
    assert stdlib_only()
    print("tool_system_01 OK: discovery, search, ranked")


if __name__ == "__main__":
    main()
