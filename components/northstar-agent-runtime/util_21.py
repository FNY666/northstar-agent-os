"""Math helpers: clamp, lerp, mean, stdev, percentile. What this IS: basic stats without numpy. What this IS NOT: not a stats library."""

from __future__ import annotations

import ast
import math
import statistics

#: Module version.
UTIL_21_VERSION = "util-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-21.v1"


class MathError(Exception):
    """Math helper failure."""


def clamp(x, lo, hi):
    if lo > hi:
        raise MathError("lo > hi")
    return max(lo, min(hi, x))


def lerp(a, b, t):
    return a + (b - a) * t


def mean(xs):
    xs = list(xs)
    if not xs:
        raise MathError("empty")
    return statistics.fmean(xs)


def stdev(xs):
    xs = list(xs)
    if len(xs) < 2:
        raise MathError("need 2+ values")
    return statistics.stdev(xs)


def percentile(xs, p):
    xs = sorted(xs)
    if not xs:
        raise MathError("empty")
    if not 0 <= p <= 100:
        raise MathError("p must be in [0, 100]")
    k = (len(xs) - 1) * p / 100
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'math', 'pathlib', 'statistics']
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
    assert clamp(5, 0, 3) == 3
    assert clamp(-1, 0, 3) == 0
    assert lerp(0, 10, 0.5) == 5.0
    assert mean([1, 2, 3]) == 2.0
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([1, 2, 3, 4], 0) == 1
    print("math helpers OK")


if __name__ == "__main__":
    main()
