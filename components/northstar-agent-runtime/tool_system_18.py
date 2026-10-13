"""Tool analytics (mock): call/latency statistics, Simulated.

AnalyticsCollector records per-call events (tool name, latency in
milliseconds, success flag) and computes aggregate statistics:
call counts, error rates, sorted-index p50/p95 latencies, and a
top-N tools ranking by call count.  Events can be windowed: old
events expire when touched after the window elapsed.

Time is injectable for tests.

What this IS:
* In-memory call/latency statistics for tool usage.

What this IS NOT:
* Not a real observability backend -- no export, no dashboards.
* Not statistical inference -- percentiles are simple sorted
  indexes, no significance testing.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

#: Module version.
TOOL_SYSTEM_18_VERSION = "tool-system-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-18.v1"


class ToolSystem18Error(Exception):
    """Fail-closed."""


@dataclass
class _Event:
    tool: str
    latency_ms: float
    success: bool
    timestamp: float


@dataclass(frozen=True)
class ToolStats:
    tool: str
    count: int
    errors: int
    error_rate: float
    p50_ms: float
    p95_ms: float
    mean_ms: float


class AnalyticsCollector:
    """Mock tool analytics with windowed reset."""

    def __init__(
        self,
        clock: Optional[Callable[[], float]] = None,
        window_seconds: Optional[float] = None,
    ) -> None:
        self._clock = clock or time.time
        if window_seconds is not None and window_seconds <= 0:
            raise ToolSystem18Error("window_seconds must be positive")
        self._window_seconds = window_seconds
        self._events: List[_Event] = []

    def record(self, tool: str, latency_ms: float, success: bool) -> None:
        """Record one tool call event."""
        if not tool:
            raise ToolSystem18Error("tool required")
        if latency_ms < 0:
            raise ToolSystem18Error("latency_ms cannot be negative")
        self._prune()
        self._events.append(
            _Event(
                tool=tool,
                latency_ms=latency_ms,
                success=bool(success),
                timestamp=self._clock(),
            )
        )

    def _prune(self) -> None:
        if self._window_seconds is None:
            return
        cutoff = self._clock() - self._window_seconds
        self._events = [e for e in self._events if e.timestamp >= cutoff]

    def reset(self) -> None:
        """Clear all recorded events."""
        self._events = []

    @staticmethod
    def _percentile(sorted_vals: List[float], pct: float) -> float:
        if not sorted_vals:
            return 0.0
        idx = min(len(sorted_vals) - 1, int(pct / 100.0 * len(sorted_vals)))
        return sorted_vals[idx]

    def stats(self, tool: str) -> ToolStats:
        """Aggregate statistics for one tool."""
        if not tool:
            raise ToolSystem18Error("tool required")
        self._prune()
        latencies = sorted(
            e.latency_ms for e in self._events if e.tool == tool
        )
        if not latencies:
            raise ToolSystem18Error(f"no events for tool '{tool}'")
        count = len(latencies)
        errors = sum(
            1 for e in self._events if e.tool == tool and not e.success
        )
        return ToolStats(
            tool=tool,
            count=count,
            errors=errors,
            error_rate=errors / count,
            p50_ms=self._percentile(latencies, 50.0),
            p95_ms=self._percentile(latencies, 95.0),
            mean_ms=sum(latencies) / count,
        )

    def top_tools(self, n: int) -> List[Tuple[str, int]]:
        """Top n tools by call count, ties broken by name."""
        if n <= 0:
            raise ToolSystem18Error("n must be positive")
        self._prune()
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.tool] = counts.get(e.tool, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:n]


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
    ac = AnalyticsCollector(clock=lambda: now["t"])
    for i in range(10):
        ac.record("search", latency_ms=float(i * 10), success=i != 3)
    ac.record("code", latency_ms=5.0, success=True)
    st = ac.stats("search")
    assert st.count == 10
    assert st.errors == 1
    assert abs(st.error_rate - 0.1) < 1e-9
    assert st.p50_ms == 50.0
    assert st.p95_ms == 90.0
    assert abs(st.mean_ms - 45.0) < 1e-9
    top = ac.top_tools(2)
    assert top == [("search", 10), ("code", 1)]
    try:
        ac.stats("nope")
        raise AssertionError("should raise")
    except ToolSystem18Error:
        pass
    # Windowed reset.
    wac = AnalyticsCollector(clock=lambda: now["t"], window_seconds=10.0)
    wac.record("search", latency_ms=1.0, success=True)
    now["t"] = 11.0
    assert wac.top_tools(1) == []
    # Manual reset.
    ac.reset()
    assert ac.top_tools(1) == []
    assert stdlib_only()
    print("tool_system_18 OK: stats, percentiles, top, windows")


if __name__ == "__main__":
    main()
