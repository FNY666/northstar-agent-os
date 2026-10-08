"""Memoized Longest Arithmetic Subsequence: memoization example.

Longest arithmetic subsequence: for each pair (j, i) extend the chain ending at j with the same difference. The (i, diff) cache gives O(n^2).

What this IS: a real memoized LAS length over an (index, difference) cache.
What this IS NOT: an arithmetic-subarray solver; the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_43_VERSION = "memo-longest-arithmetic-subseq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-longest-arithmetic-subseq.v1"


class MemoError(Exception):
    """Fail-closed."""


def las_length(nums: tuple, _cache: dict | None = None) -> int:
    """Memoized longest arithmetic subsequence length."""
    cache: dict = _cache if _cache is not None else {}
    n = len(nums)
    if n <= 2:
        return n
    best = 2
    for i in range(n):
        for j in range(i):
            d = nums[i] - nums[j]
            prev = cache.get((j, d), 1)
            cache[(i, d)] = prev + 1
            best = max(best, cache[(i, d)])
    return best

def test_las_length_example():
    assert las_length((3, 6, 9, 12)) == 4


def test_las_length_two():
    assert las_length((1, 5)) == 2


def test_las_length_mixed():
    assert las_length((9, 4, 7, 2, 10)) == 3

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
    test_las_length_example()
    test_las_length_two()
    test_las_length_mixed()
    assert stdlib_only()
    print("memo-43 OK: longest-arithmetic-subseq")


if __name__ == "__main__":
    main()
