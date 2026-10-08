"""Minimum Groups For Intervals: difference array example.

LeetCode 2406: intervals [l, r] inclusive; minimum groups so no two intervals in one group overlap. Equals the max overlap depth.

What this IS: the real max-depth sweep with inclusive ends, fail-closed on bad intervals
What this IS NOT: a greedy group assignment simulation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_13_VERSION = "min-groups-intervals.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-min-groups-intervals.v1"


class DiffError(Exception):
    """Fail-closed."""


def min_groups(intervals: list) -> int:
    """intervals: list of (l, r) inclusive. Returns min groups needed."""
    if not intervals:
        return 0
    diff = {}
    for l, r in intervals:
        if l > r:
            raise DiffError("need l <= r")
        diff[l] = diff.get(l, 0) + 1
        diff[r + 1] = diff.get(r + 1, 0) - 1
    cur = 0
    best = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > best:
            best = cur
    return best

def test_disjoint():
    assert min_groups([[1, 3], [5, 6], [8, 10], [11, 13]]) == 1


def test_triple_overlap():
    assert min_groups([[1, 3], [2, 4], [3, 5]]) == 3


def test_empty():
    assert min_groups([]) == 0


def test_bad():
    try:
        min_groups([[5, 2]])
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
    test_disjoint()
    test_triple_overlap()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-13 OK: min-groups-intervals")


if __name__ == "__main__":
    main()
