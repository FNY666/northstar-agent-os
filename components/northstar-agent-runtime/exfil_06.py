"""Timing channel detection (timing-channel), Simulated.

Detects timing-based covert channels: inter-arrival times clustered into two tight, well-separated groups suggest binary encoding.

What this IS: a bimodal timing distribution detector.

What this IS NOT:
* Heuristic -- legitimate bursty traffic can look bimodal.
* Needs 20+ samples; not real-time.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import random

#: Module version.
EXFIL_06_VERSION = "exfil-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-06.v1"


class Exfil06Error(Exception):
    """Fail-closed."""


def _mean(xs):
    return sum(xs) / len(xs)


def _var(xs):
    mu = _mean(xs)
    return sum((x - mu) ** 2 for x in xs) / len(xs)


def detect_timing_channel(intervals: List[float]) -> tuple:
    """Detect timing covert channel. Returns (suspicious, reason)."""
    if not isinstance(intervals, list) or len(intervals) < 20:
        return False, "insufficient samples"
    if any(not isinstance(x, (int, float)) or x < 0 for x in intervals):
        raise Exfil06Error("intervals must be non-negative numbers")
    s = sorted(intervals)
    # split at mid-range (robust to equal-size clusters)
    split = (s[0] + s[-1]) / 2
    if split == 0:
        return False, "degenerate"
    lo = [x for x in intervals if x <= split]
    hi = [x for x in intervals if x > split]
    if not lo or not hi or min(len(lo), len(hi)) < 8:
        return False, "single cluster"
    spread = (_var(lo) ** 0.5 + _var(hi) ** 0.5) / 2 or 1e-9
    sep = _mean(hi) - _mean(lo)
    if sep / spread > 6:
        return True, "bimodal timing: sep/sigma=%.1f" % (sep / spread)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "random"}
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
    import random
    random.seed(1)
    benign = [random.gauss(0.1, 0.02) for _ in range(30)]
    ok, _ = detect_timing_channel([abs(x) for x in benign])
    assert ok is False
    covert = [0.05] * 15 + [0.5] * 15
    ok, _ = detect_timing_channel(covert)
    assert ok is True
    assert stdlib_only()
    print("exfil-06 OK: timing channel, fail-closed")


if __name__ == "__main__":
    main()
