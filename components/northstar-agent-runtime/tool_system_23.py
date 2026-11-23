"""Tool rollback manager: version history with pins, Simulated.

RollbackManager keeps a per-tool version history of (version,
timestamp) entries.  rollback_to(version) restores a version found in
history and truncates later entries; pin(version) forbids rolling back
past that version.  Every rollback is appended to an audit log.

What this IS:
* History-based rollback with pinning and an audit trail (Simulated).

What this IS NOT:
* Not an automatic recovery -- rollback is an explicit call.
* Not a live deployer -- versions are labels, not running code.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

#: Module version.
TOOL_SYSTEM_23_VERSION = "tool-system-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-23.v1"


class ToolSystem23Error(Exception):
    """Fail-closed."""


@dataclass
class _HistoryEntry:
    version: str
    ts: float


@dataclass
class _AuditEvent:
    tool: str
    from_version: str
    to_version: str
    ts: float


class RollbackManager:
    """Per-tool version history with pinned rollback floor (Simulated)."""

    def __init__(
        self, clock: Optional[Callable[[], float]] = None
    ) -> None:
        self._clock = clock or time.time
        self._history: Dict[str, List[_HistoryEntry]] = {}
        self._pins: Dict[str, str] = {}
        self._audit: List[_AuditEvent] = []

    def record_deploy(self, tool: str, version: str) -> None:
        if not tool:
            raise ToolSystem23Error("tool required")
        if not version:
            raise ToolSystem23Error("version required")
        self._history.setdefault(tool, []).append(
            _HistoryEntry(version, self._clock())
        )

    def history(self, tool: str) -> List[Tuple[str, float]]:
        return [(e.version, e.ts) for e in self._history.get(tool, [])]

    def current(self, tool: str) -> str:
        entries = self._history.get(tool)
        if not entries:
            raise ToolSystem23Error(f"no history for tool '{tool}'")
        return entries[-1].version

    def pin(self, tool: str, version: str) -> None:
        """Forbid rolling back past this version."""
        versions = [v for v, _ in self.history(tool)]
        if version not in versions:
            raise ToolSystem23Error(
                f"version '{version}' not in history for '{tool}'"
            )
        self._pins[tool] = version

    def rollback_to(self, tool: str, version: str) -> str:
        """Roll back; requires version in history and not past the pin."""
        entries = self._history.get(tool)
        if not entries:
            raise ToolSystem23Error(f"no history for tool '{tool}'")
        versions = [e.version for e in entries]
        if version not in versions:
            raise ToolSystem23Error(
                f"version '{version}' not in history for '{tool}'"
            )
        pinned = self._pins.get(tool)
        if pinned is not None and versions.index(version) < versions.index(
            pinned
        ):
            raise ToolSystem23Error(
                f"pinned at '{pinned}'; cannot roll back past it"
            )
        idx = versions.index(version)
        prev = entries[-1].version
        self._history[tool] = entries[: idx + 1]
        self._audit.append(
            _AuditEvent(tool, prev, version, self._clock())
        )
        return version

    def audit_log(self) -> List[Dict[str, object]]:
        return [
            {
                "tool": e.tool,
                "from": e.from_version,
                "to": e.to_version,
                "ts": e.ts,
            }
            for e in self._audit
        ]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    now = {"t": 2000.0}
    rm = RollbackManager(clock=lambda: now["t"])
    rm.record_deploy("search", "v1")
    now["t"] = 2001.0
    rm.record_deploy("search", "v2")
    now["t"] = 2002.0
    rm.record_deploy("search", "v3")
    assert rm.current("search") == "v3"
    assert [v for v, _ in rm.history("search")] == ["v1", "v2", "v3"]
    # Roll back to v2.
    now["t"] = 2003.0
    assert rm.rollback_to("search", "v2") == "v2"
    assert rm.current("search") == "v2"
    audit = rm.audit_log()
    assert len(audit) == 1
    assert audit[0] == {
        "tool": "search",
        "from": "v3",
        "to": "v2",
        "ts": 2003.0,
    }
    # Unknown version.
    try:
        rm.rollback_to("search", "v9")
        raise AssertionError("should raise")
    except ToolSystem23Error:
        pass
    # Pin at v2: rollback past it to v1 fails, to v2 itself ok.
    rm.pin("search", "v2")
    try:
        rm.rollback_to("search", "v1")
        raise AssertionError("should raise")
    except ToolSystem23Error:
        pass
    now["t"] = 2004.0
    rm.record_deploy("search", "v3")
    assert rm.rollback_to("search", "v2") == "v2"
    assert len(rm.audit_log()) == 2
    # Unknown tool.
    try:
        rm.current("nope")
        raise AssertionError("should raise")
    except ToolSystem23Error:
        pass
    # Pin to a version not in history.
    try:
        rm.pin("search", "v9")
        raise AssertionError("should raise")
    except ToolSystem23Error:
        pass
    assert stdlib_only()
    print("tool_system_23 OK: history, rollback, pin, audit")


if __name__ == "__main__":
    main()
