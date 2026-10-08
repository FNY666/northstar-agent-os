"""Time-based access control, Simulated.

Allows actions only inside configured (weekday, start_hour, end_hour)
windows.  Weekday: Monday=0 .. Sunday=6.

What this IS: business-hours / maintenance-window enforcement.

What this IS NOT:
* Not timezone-aware beyond the datetime the host passes in.
* No windows configured -> FAIL CLOSED (deny).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

#: Module version.
DEF_EXTRA_04_VERSION = "def-extra-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-04.v1"


class TimeAccessError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TimeWindow:
    """Allowed window: weekday + [start_hour, end_hour)."""

    weekday: int  # 0=Monday .. 6=Sunday
    start_hour: int  # 0..23
    end_hour: int  # 1..24, exclusive

    def __post_init__(self) -> None:
        if not 0 <= self.weekday <= 6:
            raise TimeAccessError("weekday must be 0..6")
        if not 0 <= self.start_hour <= 23:
            raise TimeAccessError("start_hour must be 0..23")
        if not 1 <= self.end_hour <= 24:
            raise TimeAccessError("end_hour must be 1..24")
        if self.end_hour <= self.start_hour:
            raise TimeAccessError("end_hour must be after start_hour")


class TimeAccessControl:
    """Allow only inside configured windows."""

    def __init__(self, windows: List[TimeWindow]) -> None:
        self._windows = list(windows)

    def is_allowed(self, when: Optional[datetime] = None) -> bool:
        """Return True if `when` (default now) falls in any window."""
        moment = datetime.now() if when is None else when
        if not self._windows:
            return False
        for window in self._windows:
            if (
                moment.weekday() == window.weekday
                and window.start_hour <= moment.hour < window.end_hour
            ):
                return True
        return False


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "datetime", "pathlib", "typing"}
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
    """Self-check."""
    # Monday 2026-10-05 10:30.
    monday = datetime(2026, 10, 5, 10, 30)
    tac = TimeAccessControl([TimeWindow(0, 9, 18)])
    assert tac.is_allowed(monday) is True
    # Monday 20:00 -> outside window.
    assert tac.is_allowed(datetime(2026, 10, 5, 20, 0)) is False
    # Tuesday 10:30 -> wrong weekday.
    assert tac.is_allowed(datetime(2026, 10, 6, 10, 30)) is False
    # No windows -> fail closed.
    assert TimeAccessControl([]).is_allowed(monday) is False
    # Boundary: end_hour exclusive.
    assert tac.is_allowed(datetime(2026, 10, 5, 18, 0)) is False
    assert stdlib_only()
    print("def-extra-04 OK: windows, boundaries, fail-closed")


if __name__ == "__main__":
    main()
