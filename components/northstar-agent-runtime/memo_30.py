"""Memoized Max Sum Increasing Subsequence: memoization example.

Max-sum (not longest) increasing subsequence via (i, prev) states: take adds nums[i], skip keeps prev. The cache gives O(n^2) states.

What this IS: a real memoized max-sum increasing subsequence.
What this IS NOT: an LIS length solver (see memo-09); the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_30_VERSION = "memo-max-sum-increasing-subseq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-max-sum-increasing-subseq.v1"


class MemoError(Exception):
    """Fail-closed."""


def msis(nums: tuple, i: int = 0, prev: int | None = None, _cache: dict | None = None) -> int:
    """Memoized max-sum increasing subsequence."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, prev)
    if key in cache:
        return cache[key]
    if i >= len(nums):
        cache[key] = 0
    elif prev is not None and nums[i] <= prev:
        cache[key] = msis(nums, i + 1, prev, cache)
    else:
        cache[key] = max(nums[i] + msis(nums, i + 1, nums[i], cache), msis(nums, i + 1, prev, cache))
    return cache[key]

def test_msis_example():
    assert msis((1, 101, 2, 3, 100, 4, 5)) == 106


def test_msis_sorted():
    assert msis((1, 2, 3)) == 6


def test_msis_empty():
    assert msis(()) == 0

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
    test_msis_example()
    test_msis_sorted()
    test_msis_empty()
    assert stdlib_only()
    print("memo-30 OK: max-sum-increasing-subseq")


if __name__ == "__main__":
    main()
