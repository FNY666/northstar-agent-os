"""Zero Array Via Range Decrements: difference array example.

LeetCode 3355 simplified: queries (l, r, val) decrement a range; check whether every element of nums can be reduced to exactly zero.

What this IS: the real capacity-vs-demand check via difference array, fail-closed on bad queries
What this IS NOT: a greedy simulation applying queries one by one
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_07_VERSION = "zero-array-check.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-zero-array-check.v1"


class DiffError(Exception):
    """Fail-closed."""


def can_zero_array(nums: list, queries: list) -> bool:
    """True iff total decrement capacity covers nums at every index."""
    n = len(nums)
    diff = [0] * (n + 1)
    for l, r, v in queries:
        if not (0 <= l <= r < n) or v < 0:
            raise DiffError("bad query")
        diff[l] += v
        diff[r + 1] -= v
    cur = 0
    for i, x in enumerate(nums):
        cur += diff[i]
        if cur < x:
            return False
    return True

def test_possible():
    assert can_zero_array([2, 0, 2], [[0, 2, 1], [0, 2, 1], [1, 1, 3]]) is True


def test_impossible():
    assert can_zero_array([4, 3, 2, 1], [[1, 3, 2], [0, 2, 1]]) is False


def test_no_queries():
    assert can_zero_array([0, 0], []) is True
    assert can_zero_array([1], []) is False


def test_bad_query():
    try:
        can_zero_array([1, 2], [[0, 5, 1]])
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
    test_possible()
    test_impossible()
    test_no_queries()
    test_bad_query()
    assert stdlib_only()
    print("diff-07 OK: zero-array-check")


if __name__ == "__main__":
    main()
