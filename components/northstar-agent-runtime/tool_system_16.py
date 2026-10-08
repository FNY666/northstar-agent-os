"""Tool quotas: per-tool usage limits, Simulated.

QuotaManager enforces a fixed per-tool call budget inside a time
window.  Each tool has a limit and a window length in seconds; calls
consume from the budget and raise QuotaExceeded when the current
window's budget is exhausted.  A new window implicitly starts the
next time the tool is touched after the old window expired.

Time is injectable for tests.

What this IS:
* Per-tool usage quotas with windowed reset.

What this IS NOT:
* Not persistent -- all state lives in memory.
* Not a rate limiter (no refill curve; see tool_system_15).
* Not distributed.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

#: Module version.
TOOL_SYSTEM_16_VERSION = "tool-system-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-16.v1"


class ToolSystem16Error(Exception):
    """Fail-closed."""


class QuotaExceeded(ToolSystem16Error):
    """Raised when a tool's quota is exhausted for the current window."""


@dataclass
class _Quota:
    limit: int
    window_seconds: float
    used: int = 0
    window_start: float = 0.0


class QuotaManager:
    """Per-tool usage quotas with windowed resets."""

    def __init__(self, clock: Optional[Callable[[], float]] = None) -> None:
        self._clock = clock or time.time
        self._quotas: Dict[str, _Quota] = {}

    def set_quota(
        self, tool: str, limit: int, window_seconds: float
    ) -> None:
        """Set (or replace) the quota for a tool.  Resets usage."""
        if not tool:
            raise ToolSystem16Error("tool required")
        if limit <= 0:
            raise ToolSystem16Error("limit must be positive")
        if window_seconds <= 0:
            raise ToolSystem16Error("window_seconds must be positive")
        self._quotas[tool] = _Quota(
            limit=limit,
            window_seconds=window_seconds,
            used=0,
            window_start=self._clock(),
        )

    def _roll_window(self, quota: _Quota) -> None:
        now = self._clock()
        if now - quota.window_start >= quota.window_seconds:
            quota.used = 0
            quota.window_start = now

    def consume(self, tool: str, count: int = 1) -> None:
        """Consume quota; raises QuotaExceeded when exhausted."""
        if tool not in self._quotas:
            raise ToolSystem16Error(f"no quota set for tool '{tool}'")
        if count <= 0:
            raise ToolSystem16Error("count must be positive")
        quota = self._quotas[tool]
        self._roll_window(quota)
        if quota.used + count > quota.limit:
            raise QuotaExceeded(
                f"tool '{tool}' quota exceeded "
                f"(limit {quota.limit}, used {quota.used})"
            )
        quota.used += count

    def remaining(self, tool: str) -> int:
        """Quota remaining in the current window."""
        if tool not in self._quotas:
            raise ToolSystem16Error(f"no quota set for tool '{tool}'")
        quota = self._quotas[tool]
        self._roll_window(quota)
        return quota.limit - quota.used

    def reset_window(self, tool: str) -> None:
        """Manually start a fresh window for a tool (usage cleared)."""
        if tool not in self._quotas:
            raise ToolSystem16Error(f"no quota set for tool '{tool}'")
        quota = self._quotas[tool]
        quota.used = 0
        quota.window_start = self._clock()

    def tools(self) -> List[str]:
        return sorted(self._quotas)


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
    now = {"t": 0.0}
    qm = QuotaManager(clock=lambda: now["t"])
    qm.set_quota("search", limit=2, window_seconds=60.0)
    assert qm.remaining("search") == 2
    qm.consume("search")
    assert qm.remaining("search") == 1
    qm.consume("search")
    assert qm.remaining("search") == 0
    try:
        qm.consume("search")
        raise AssertionError("should raise")
    except QuotaExceeded:
        pass
    # Window expiry starts a fresh window.
    now["t"] = 61.0
    assert qm.remaining("search") == 2
    qm.consume("search")
    assert qm.remaining("search") == 1
    # Manual reset.
    qm.reset_window("search")
    assert qm.remaining("search") == 2
    # Unknown tool.
    try:
        qm.consume("nope")
        raise AssertionError("should raise")
    except ToolSystem16Error:
        pass
    # Bad config.
    try:
        qm.set_quota("x", limit=0, window_seconds=60)
        raise AssertionError("should raise")
    except ToolSystem16Error:
        pass
    assert stdlib_only()
    print("tool_system_16 OK: quotas, windows, exhausted")


if __name__ == "__main__":
    main()
