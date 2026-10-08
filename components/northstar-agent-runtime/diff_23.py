"""Interval Cover Count Per Point: difference array example.

Intervals [l, r] inclusive; for each query point count covering intervals via one difference sweep over sorted points.

What this IS: a real offline sweep answering all point queries, fail-closed on bad intervals
What this IS NOT: a per-point scan over all intervals
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_23_VERSION = "interval-cover-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-interval-cover-count.v1"


class DiffError(Exception):
    """Fail-closed."""


def cover_count(intervals: list, points: list) -> list:
    """Returns, per point, the number of inclusive intervals covering it."""
    diff = {}
    for l, r in intervals:
        if l > r:
            raise DiffError("need l <= r")
        diff[l] = diff.get(l, 0) + 1
        diff[r + 1] = diff.get(r + 1, 0) - 1
    events = sorted(diff)
    order = sorted(range(len(points)), key=lambda i: points[i])
    res = [0] * len(points)
    cur = 0
    e = 0
    for i in order:
        while e < len(events) and events[e] <= points[i]:
            cur += diff[events[e]]
            e += 1
        res[i] = cur
    return res

def test_basic():
    assert cover_count([[1, 4], [2, 6], [8, 10]], [2, 5, 9]) == [2, 1, 1]


def test_none_cover():
    assert cover_count([[1, 2]], [5]) == [0]


def test_empty_intervals():
    assert cover_count([], [1, 2]) == [0, 0]


def test_bad():
    try:
        cover_count([[4, 1]], [2])
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
    test_none_cover()
    test_empty_intervals()
    test_bad()
    assert stdlib_only()
    print("diff-23 OK: interval-cover-count")


if __name__ == "__main__":
    main()
