"""obs_10: Histogram buckets, Simulated.

Cumulative histogram: each bucket counts observations <= its upper bound.
Standard Prometheus-style buckets.

Fail-closed: non-numeric observations raise.
Stdlib only.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List

OBS10_VERSION = "obs-10.v1"
SCHEMA_PIN = "northstar.obs-10.v1"


class Obs10Error(Exception):
    """Fail-closed."""


class Histogram:
    """Cumulative histogram with fixed buckets."""

    def __init__(self, buckets: List[float]) -> None:
        if not buckets:
            raise Obs10Error("buckets required")
        for b in buckets:
            if not isinstance(b, (int, float)) or not math.isfinite(b):
                raise Obs10Error("buckets must be finite numbers")
        sorted_b = sorted(buckets)
        if sorted_b != list(buckets):
            raise Obs10Error("buckets must be sorted ascending")
        self._buckets = [float(b) for b in buckets]
        self._counts = [0] * len(buckets)
        self._sum = 0.0
        self._total = 0

    def observe(self, value: float) -> None:
        """Record one observation."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise Obs10Error("value must be numeric")
        if not math.isfinite(value):
            raise Obs10Error("value must be finite")
        v = float(value)
        for i, bound in enumerate(self._buckets):
            if v <= bound:
                self._counts[i] += 1
        self._sum += v
        self._total += 1

    def counts(self) -> Dict[str, int]:
        """Bucket upper bound -> cumulative count."""
        return {str(b): c for b, c in zip(self._buckets, self._counts)}

    @property
    def total(self) -> int:
        return self._total

    @property
    def sum(self) -> float:
        return self._sum


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
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
    h = Histogram([1.0, 5.0, 10.0])
    h.observe(0.5)
    h.observe(3.0)
    h.observe(7.0)
    h.observe(20.0)  # above all buckets
    c = h.counts()
    assert c["1.0"] == 1 and c["5.0"] == 2 and c["10.0"] == 3
    assert h.total == 4
    try:
        h.observe("bad")  # type: ignore
        raise AssertionError("should raise")
    except Obs10Error:
        pass
    try:
        Histogram([5.0, 1.0])  # unsorted
        raise AssertionError("should raise")
    except Obs10Error:
        pass
    assert stdlib_only()
    print("obs_10 OK")


if __name__ == "__main__":
    main()
