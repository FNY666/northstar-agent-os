"""Maximum Overlap Count: difference array example.

Intervals [l, r) half-open; the maximum number overlapping at any point, via a sparse difference sweep.

What this IS: a real half-open sweep for max overlap, fail-closed on bad intervals
What this IS NOT: checking every pair of intervals
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_14_VERSION = "max-overlap-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-overlap-count.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_overlap(intervals: list) -> int:
    """intervals: list of (l, r) half-open. Returns max overlap count."""
    if not intervals:
        return 0
    diff = {}
    for l, r in intervals:
        if not (l < r):
            raise DiffError("need l < r")
        diff[l] = diff.get(l, 0) + 1
        diff[r] = diff.get(r, 0) - 1
    cur = 0
    best = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > best:
            best = cur
    return best

def test_basic():
    assert max_overlap([[1, 5], [2, 6], [4, 8]]) == 3


def test_disjoint():
    assert max_overlap([[1, 2], [3, 4]]) == 1


def test_empty():
    assert max_overlap([]) == 0


def test_bad():
    try:
        max_overlap([[2, 2]])
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
    test_disjoint()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-14 OK: max-overlap-count")


if __name__ == "__main__":
    main()
