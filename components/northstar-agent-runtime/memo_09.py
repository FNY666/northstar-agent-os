"""Memoized Longest Increasing Subsequence: memoization example.

LIS length via (i, prev_val) states: either take nums[i] when it extends the tail or skip it. The cache gives O(n^2) states.

What this IS: a real memoized LIS length, fail-closed on nothing but honest about input type.
What this IS NOT: an O(n log n) patience implementation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_09_VERSION = "memo-lis.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-lis.v1"


class MemoError(Exception):
    """Fail-closed."""


def lis_length(nums: tuple, i: int = 0, prev_val: int | None = None, _cache: dict | None = None) -> int:
    """Memoized longest increasing subsequence length."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, prev_val)
    if key in cache:
        return cache[key]
    if i >= len(nums):
        cache[key] = 0
    elif prev_val is not None and nums[i] <= prev_val:
        cache[key] = lis_length(nums, i + 1, prev_val, cache)
    else:
        cache[key] = max(
            1 + lis_length(nums, i + 1, nums[i], cache),
            lis_length(nums, i + 1, prev_val, cache),
        )
    return cache[key]

def test_lis_example():
    assert lis_length((10, 9, 2, 5, 3, 7, 101, 18)) == 4


def test_lis_sorted():
    assert lis_length((1, 2, 3, 4)) == 4


def test_lis_empty():
    assert lis_length(()) == 0

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
    test_lis_example()
    test_lis_sorted()
    test_lis_empty()
    assert stdlib_only()
    print("memo-09 OK: lis")


if __name__ == "__main__":
    main()
