"""Memoized Jump Game II: memoization example.

Minimum jumps to the last index: 1 + min over reachable next positions. The index cache gives O(n^2) worst case.

What this IS: a real memoized min-jump solver returning infinity for unreachable tails.
What this IS NOT: a greedy O(n) solver; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_17_VERSION = "memo-jump-game-ii.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-jump-game-ii.v1"


class MemoError(Exception):
    """Fail-closed."""


def min_jumps(nums: tuple, i: int = 0, _cache: dict | None = None) -> float:
    """Memoized minimum jumps from i to the end."""
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i >= len(nums) - 1:
        cache[i] = 0
    else:
        best = float("inf")
        for step in range(1, nums[i] + 1):
            if i + step < len(nums):
                best = min(best, 1 + min_jumps(nums, i + step, cache))
        cache[i] = best
    return cache[i]

def test_min_jumps_example():
    assert min_jumps((2, 3, 1, 1, 4)) == 2


def test_min_jumps_zero_gap():
    assert min_jumps((2, 3, 0, 1, 4)) == 2


def test_min_jumps_single():
    assert min_jumps((0,)) == 0

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
    test_min_jumps_example()
    test_min_jumps_zero_gap()
    test_min_jumps_single()
    assert stdlib_only()
    print("memo-17 OK: jump-game-ii")


if __name__ == "__main__":
    main()
