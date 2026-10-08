"""Minimum Meeting Rooms: difference array example.

LeetCode 253: intervals [start, end) half-open; minimum rooms so no overlap in one room, via a sparse difference sweep.

What this IS: the real sweep for min rooms, fail-closed on bad intervals
What this IS NOT: sorting starts and ends separately
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_15_VERSION = "meeting-rooms-ii.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-meeting-rooms-ii.v1"


class DiffError(Exception):
    """Fail-closed."""


def min_meeting_rooms(intervals: list) -> int:
    """intervals: list of (start, end) half-open. Returns min rooms."""
    if not intervals:
        return 0
    diff = {}
    for s, e in intervals:
        if not (s < e):
            raise DiffError("need start < end")
        diff[s] = diff.get(s, 0) + 1
        diff[e] = diff.get(e, 0) - 1
    cur = 0
    best = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > best:
            best = cur
    return best

def test_example():
    assert min_meeting_rooms([[0, 30], [5, 10], [15, 20]]) == 2


def test_disjoint():
    assert min_meeting_rooms([[7, 10], [2, 4]]) == 1


def test_empty():
    assert min_meeting_rooms([]) == 0


def test_bad():
    try:
        min_meeting_rooms([[5, 5]])
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
    test_example()
    test_disjoint()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-15 OK: meeting-rooms-ii")


if __name__ == "__main__":
    main()
