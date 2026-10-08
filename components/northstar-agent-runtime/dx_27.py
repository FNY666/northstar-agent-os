"""DX-27: Changelog generation (mock), Simulated.

Collect typed entries (feat/fix/docs/perf/refactor); `render()` emits
Keep-a-Changelog-style markdown grouped by type in a fixed order.
Unknown entry types raise at add time.

What this IS: grouped markdown rendering of explicit entries.
What this IS NOT: not parsed from git history.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

#: Module version.
DX27_CHANGELOG_VERSION = "dx-changelog.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-changelog.v1"

#: Entry types in render order with headings.
ENTRY_TYPES = ("feat", "fix", "docs", "perf", "refactor")
_TYPE_HEADINGS = {
    "feat": "Added",
    "fix": "Fixed",
    "docs": "Docs",
    "perf": "Performance",
    "refactor": "Refactored",
}


class ChangelogError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ChangelogEntry:
    entry_type: str
    scope: str
    message: str


class Changelog:
    """Explicit changelog entry collector."""

    def __init__(self) -> None:
        self._entries: List[ChangelogEntry] = []

    def add(self, entry: ChangelogEntry) -> None:
        if entry.entry_type not in _TYPE_HEADINGS:
            raise ChangelogError(f"unknown entry type '{entry.entry_type}'")
        if not entry.message:
            raise ChangelogError("message required")
        self._entries.append(entry)

    def count(self, entry_type: Optional[str] = None) -> int:
        if entry_type is not None and entry_type not in _TYPE_HEADINGS:
            raise ChangelogError(f"unknown entry type '{entry_type}'")
        return sum(
            1 for e in self._entries
            if entry_type is None or e.entry_type == entry_type
        )

    def render(self) -> str:
        lines = ["# Changelog", ""]
        for etype in ENTRY_TYPES:
            group = [e for e in self._entries if e.entry_type == etype]
            if not group:
                continue
            lines.append(f"## {_TYPE_HEADINGS[etype]}")
            for e in group:
                prefix = f"**{e.scope}:** " if e.scope else ""
                lines.append(f"- {prefix}{e.message}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    @property
    def types(self) -> List[str]:
        return list(ENTRY_TYPES)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    log = Changelog()
    log.add(ChangelogEntry("fix", "gate", "block recursive bombs"))
    log.add(ChangelogEntry("feat", "dx", "code actions"))
    log.add(ChangelogEntry("fix", "", "typo"))
    out = log.render()
    assert out.index("## Added") < out.index("## Fixed")
    assert "- **gate:** block recursive bombs" in out
    assert "- typo" in out
    assert log.count("fix") == 2
    assert log.count() == 3
    try:
        log.add(ChangelogEntry("chore", "x", "y"))
        raise AssertionError("should raise")
    except ChangelogError:
        pass
    try:
        log.add(ChangelogEntry("fix", "x", ""))
        raise AssertionError("should raise")
    except ChangelogError:
        pass
    assert stdlib_only()
    print("dx_27 OK: grouped render, ordering, counts, validation")


if __name__ == "__main__":
    main()
