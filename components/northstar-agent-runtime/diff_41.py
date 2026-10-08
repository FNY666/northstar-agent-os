"""Weighted Overlap Maximum: difference array example.

Intervals (l, r, w) half-open with weights; the maximum total weight at any point via a weighted sparse difference sweep.

What this IS: a real weighted sweep, fail-closed on bad intervals
What this IS NOT: an unweighted overlap count
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_41_VERSION = "weighted-overlap-max.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-weighted-overlap-max.v1"


class DiffError(Exception):
    """Fail-closed."""


def weighted_overlap_max(intervals: list) -> int:
    """intervals: list of (l, r, w). Returns max total weight."""
    if not intervals:
        return 0
    d = {}
    for l, r, w in intervals:
        if not (l < r) or w < 0:
            raise DiffError("bad interval")
        d[l] = d.get(l, 0) + w
        d[r] = d.get(r, 0) - w
    cur = 0
    best = 0
    for k in sorted(d):
        cur += d[k]
        if cur > best:
            best = cur
    return best

def test_basic():
    assert weighted_overlap_max([(1, 4, 5), (2, 5, 7), (6, 8, 3)]) == 12


def test_single():
    assert weighted_overlap_max([(0, 10, 4)]) == 4


def test_empty():
    assert weighted_overlap_max([]) == 0


def test_bad():
    try:
        weighted_overlap_max([(2, 2, 1)])
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
    test_basic()
    test_single()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-41 OK: weighted-overlap-max")


if __name__ == "__main__":
    main()
