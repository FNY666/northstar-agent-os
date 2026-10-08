"""DX-23: Benchmark runners (mock), Simulated.

Register named benchmarks with canned per-rep durations. `run(name,
reps)` cycles through the canned durations and returns min/mean/max.
Negative durations are rejected at registration; unknown names raise.

What this IS: canned timing stats for benchmark UI plumbing.
What this IS NOT: not measuring real performance.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX23_BENCH_VERSION = "dx-bench.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-bench.v1"


class BenchError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class BenchStats:
    name: str
    unit: str
    reps: int
    min: float
    mean: float
    max: float


class BenchmarkRunner:
    """Canned benchmark stats."""

    def __init__(self) -> None:
        self._benches: Dict[str, List[float]] = {}
        self._units: Dict[str, str] = {}

    def register(self, name: str, durations: List[float], unit: str = "ms") -> None:
        if not name or not name.strip():
            raise BenchError("name required")
        if name in self._benches:
            raise BenchError(f"duplicate benchmark '{name}'")
        if not durations:
            raise BenchError("durations required")
        for d in durations:
            if not isinstance(d, (int, float)) or d < 0:
                raise BenchError("durations must be non-negative numbers")
        if not unit:
            raise BenchError("unit required")
        self._benches[name] = [float(d) for d in durations]
        self._units[name] = unit

    def run(self, name: str, reps: int = 5) -> BenchStats:
        if name not in self._benches:
            raise BenchError(f"unknown benchmark '{name}'")
        if reps < 1:
            raise BenchError("reps must be >= 1")
        canned = self._benches[name]
        samples = [canned[i % len(canned)] for i in range(reps)]
        return BenchStats(
            name=name,
            unit=self._units[name],
            reps=reps,
            min=min(samples),
            mean=sum(samples) / len(samples),
            max=max(samples),
        )

    @property
    def names(self) -> List[str]:
        return sorted(self._benches)


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
    bench = BenchmarkRunner()
    bench.register("sort", [1.0, 2.0, 3.0])
    s = bench.run("sort", reps=4)  # cycles: 1,2,3,1
    assert s.min == 1.0 and s.max == 3.0
    assert abs(s.mean - 1.75) < 1e-9
    assert s.unit == "ms" and s.reps == 4
    try:
        bench.run("nope")
        raise AssertionError("should raise")
    except BenchError:
        pass
    try:
        bench.register("neg", [-1.0])
        raise AssertionError("should raise")
    except BenchError:
        pass
    assert bench.names == ["sort"]
    assert stdlib_only()
    print("dx_23 OK: canned stats, cycling, negative/unknown rejected")


if __name__ == "__main__":
    main()
