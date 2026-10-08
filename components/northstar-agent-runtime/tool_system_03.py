"""Tool deprecation: warnings, Simulated.

Tools move through lifecycle: active -> deprecated -> removed.
Deprecated tools still work but emit warnings.  Removed tools refuse.

What this IS: graceful tool lifecycle management.

What this IS NOT:
* Not a migration engine -- just lifecycle states.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional

#: Module version.
TOOL_SYSTEM_03_VERSION = "tool-system-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-03.v1"


class ToolSystem03Error(Exception):
    """Fail-closed."""


class Lifecycle(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REMOVED = "removed"


@dataclass(frozen=True)
class ToolEntry:
    name: str
    lifecycle: Lifecycle = Lifecycle.ACTIVE
    replacement: str = ""
    deprecation_note: str = ""


class DeprecationRegistry:
    """Tracks tool lifecycle."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolEntry] = {}

    def register(self, entry: ToolEntry) -> None:
        if not entry.name:
            raise ToolSystem03Error("name required")
        self._tools[entry.name] = entry

    def deprecate(self, name: str, replacement: str = "", note: str = "") -> None:
        if name not in self._tools:
            raise ToolSystem03Error(f"unknown tool '{name}'")
        old = self._tools[name]
        self._tools[name] = ToolEntry(
            name=name,
            lifecycle=Lifecycle.DEPRECATED,
            replacement=replacement,
            deprecation_note=note,
        )

    def remove(self, name: str) -> None:
        if name not in self._tools:
            raise ToolSystem03Error(f"unknown tool '{name}'")
        old = self._tools[name]
        self._tools[name] = ToolEntry(name=name, lifecycle=Lifecycle.REMOVED)

    def check(self, name: str) -> str:
        """Returns 'ok', 'deprecated', or raises for removed/unknown."""
        if name not in self._tools:
            raise ToolSystem03Error(f"unknown tool '{name}'")
        entry = self._tools[name]
        if entry.lifecycle == Lifecycle.REMOVED:
            raise ToolSystem03Error(f"tool '{name}' was removed")
        if entry.lifecycle == Lifecycle.DEPRECATED:
            msg = f"tool '{name}' is deprecated"
            if entry.replacement:
                msg += f"; use '{entry.replacement}'"
            warnings.warn(msg, DeprecationWarning, stacklevel=3)
            return "deprecated"
        return "ok"

    def call(self, name: str, fn: Callable[[], object]) -> object:
        """Call fn after lifecycle check."""
        self.check(name)  # raises on removed/unknown, warns on deprecated
        return fn()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "enum",
        "pathlib", "typing", "warnings",
    }
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
    r = DeprecationRegistry()
    r.register(ToolEntry("new_tool"))
    assert r.check("new_tool") == "ok"
    r.register(ToolEntry("old_tool"))
    r.deprecate("old_tool", replacement="new_tool")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert r.check("old_tool") == "deprecated"
        assert len(w) == 1
        assert "new_tool" in str(w[0].message)
    r.remove("old_tool")
    try:
        r.check("old_tool")
        raise AssertionError("should raise")
    except ToolSystem03Error:
        pass
    assert stdlib_only()
    print("tool_system_03 OK: lifecycle, warnings, removal")


if __name__ == "__main__":
    main()
