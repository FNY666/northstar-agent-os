"""DX-24: Profiler UI (mock), Simulated.

Record time samples per function; `hotspots(limit)` returns the top-N
functions by total time. Negative durations raise; `reset()` clears.
Ties break by function name for determinism.

What this IS: explicit sample aggregation for flame-chart plumbing.
What this IS NOT: not sampling a real process.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX24_PROFILER_VERSION = "dx-profiler.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-profiler.v1"


class ProfilerError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Hotspot:
    function: str
    calls: int
    total_ms: float
    mean_ms: float


class Profiler:
    """Explicit time-sample aggregation."""

    def __init__(self) -> None:
        self._totals: Dict[str, float] = {}
        self._calls: Dict[str, int] = {}

    def sample(self, function: str, duration_ms: float) -> None:
        if not function or not function.strip():
            raise ProfilerError("function required")
        if not isinstance(duration_ms, (int, float)) or duration_ms < 0:
            raise ProfilerError("duration_ms must be non-negative")
        self._totals[function] = self._totals.get(function, 0.0) + float(duration_ms)
        self._calls[function] = self._calls.get(function, 0) + 1

    def hotspots(self, limit: int = 5) -> List[Hotspot]:
        if limit < 1:
            raise ProfilerError("limit must be >= 1")
        ranked = sorted(
            self._totals,
            key=lambda f: (-self._totals[f], f),
        )
        out = []
        for fn in ranked[:limit]:
            total = self._totals[fn]
            calls = self._calls[fn]
            out.append(Hotspot(fn, calls, total, total / calls))
        return out

    def reset(self) -> None:
        self._totals.clear()
        self._calls.clear()

    @property
    def functions(self) -> List[str]:
        return sorted(self._totals)


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
    prof = Profiler()
    prof.sample("parse", 10.0)
    prof.sample("parse", 20.0)
    prof.sample("emit", 5.0)
    hs = prof.hotspots(limit=2)
    assert [(h.function, h.calls, h.total_ms) for h in hs] == [
        ("parse", 2, 30.0), ("emit", 1, 5.0)
    ]
    assert hs[0].mean_ms == 15.0
    try:
        prof.sample("x", -1.0)
        raise AssertionError("should raise")
    except ProfilerError:
        pass
    prof.reset()
    assert prof.hotspots() == []
    assert stdlib_only()
    print("dx_24 OK: aggregation, ranking, reset, negative rejected")


if __name__ == "__main__":
    main()
