"""obs_11: Summary quantiles (mock), Simulated.

Mock quantile estimation over a sliding window.  NOT a production
quantile algorithm (no t-digest/CKMS) -- stores recent values and
computes exact quantiles over the window.  Labeled mock so no one
mistakes it for a streaming estimator.

Fail-closed: invalid inputs raise.
Stdlib only.
"""

from __future__ import annotations

import ast
import math
from collections import deque
from typing import Deque, List

OBS11_VERSION = "obs-11.v1"
SCHEMA_PIN = "northstar.obs-11.v1"


class Obs11Error(Exception):
    """Fail-closed."""


class MockSummary:
    """Mock summary with windowed quantiles."""

    def __init__(self, window: int = 100) -> None:
        if not isinstance(window, int) or window < 1:
            raise Obs11Error("window must be positive int")
        self._window: Deque[float] = deque(maxlen=window)

    def observe(self, value: float) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise Obs11Error("value must be numeric")
        if not math.isfinite(value):
            raise Obs11Error("value must be finite")
        self._window.append(float(value))

    def quantile(self, q: float) -> float:
        """Exact quantile over the current window (mock)."""
        if not isinstance(q, (int, float)) or not 0.0 <= q <= 1.0:
            raise Obs11Error("q must be in [0,1]")
        if not self._window:
            raise Obs11Error("no observations")
        vals = sorted(self._window)
        idx = min(int(q * len(vals)), len(vals) - 1)
        return vals[idx]

    @property
    def count(self) -> int:
        return len(self._window)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "collections", "math", "pathlib", "typing"}
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
    s = MockSummary(window=10)
    for i in range(1, 11):
        s.observe(float(i))
    assert s.quantile(0.5) == 6.0  # median of 1..10 via index
    assert s.quantile(0.0) == 1.0
    assert s.quantile(1.0) == 10.0
    try:
        s.quantile(1.5)
        raise AssertionError("should raise")
    except Obs11Error:
        pass
    try:
        s.observe("bad")  # type: ignore
        raise AssertionError("should raise")
    except Obs11Error:
        pass
    assert stdlib_only()
    print("obs_11 OK")


if __name__ == "__main__":
    main()
