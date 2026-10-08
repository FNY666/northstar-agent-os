"""Threshold Alert On Finalize: difference array example.

Range adds accumulate in a difference array; finalize() materializes and raises fail-closed if any cell exceeds the threshold.

What this IS: a real threshold-guarded materialization, fail-closed on breach
What this IS NOT: checking the threshold only at query time
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_32_VERSION = "threshold-alert.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-threshold-alert.v1"


class DiffError(Exception):
    """Fail-closed."""


class ThresholdDiff:
    """Range adds; finalize() raises if any value exceeds the threshold."""

    def __init__(self, n: int, threshold: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self.threshold = threshold
        self._d = [0] * (n + 1)

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._d[l] += v
        self._d[r + 1] -= v

    def finalize(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            cur += self._d[i]
            out.append(cur)
            if cur > self.threshold:
                raise DiffError("threshold exceeded at index %d" % i)
        return out

def test_under_threshold():
    t = ThresholdDiff(4, 10)
    t.add(0, 3, 5)
    assert t.finalize() == [5, 5, 5, 5]


def test_breach():
    t = ThresholdDiff(4, 10)
    t.add(0, 3, 5)
    t.add(1, 2, 6)
    try:
        t.finalize()
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_exact_threshold_ok():
    t = ThresholdDiff(2, 5)
    t.add(0, 1, 5)
    assert t.finalize() == [5, 5]


def test_bad_bounds():
    t = ThresholdDiff(2, 5)
    try:
        t.add(0, 2, 1)
    except DiffError:
        return
    raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_under_threshold()
    test_breach()
    test_exact_threshold_ok()
    test_bad_bounds()
    assert stdlib_only()
    print("diff-32 OK: threshold-alert")


if __name__ == "__main__":
    main()
