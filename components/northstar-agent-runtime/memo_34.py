"""Memoized Burst Balloons: memoization example.

Max coins from bursting balloons: try each k as last burst in (l, r), gaining left*nums[k]*right. The (l, r) cache gives O(n^3).

What this IS: a real memoized burst-balloon maximizer over an (l, r) cache.
What this IS NOT: a burst-order reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_34_VERSION = "memo-burst-balloons.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-burst-balloons.v1"


class MemoError(Exception):
    """Fail-closed."""


def max_coins(nums: tuple, l: int = 0, r: int | None = None, _cache: dict | None = None) -> int:
    """Memoized max coins from bursting balloons[l..r]."""
    if r is None:
        r = len(nums) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (l, r)
    if key in cache:
        return cache[key]
    if l > r:
        cache[key] = 0
    else:
        best = 0
        for k in range(l, r + 1):
            left = nums[l - 1] if l > 0 else 1
            right = nums[r + 1] if r + 1 < len(nums) else 1
            gain = max_coins(nums, l, k - 1, cache) + left * nums[k] * right + max_coins(nums, k + 1, r, cache)
            best = max(best, gain)
        cache[key] = best
    return cache[key]

def test_max_coins_example():
    assert max_coins((3, 1, 5, 8)) == 167


def test_max_coins_single():
    assert max_coins((5,)) == 5


def test_max_coins_empty():
    assert max_coins(()) == 0

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
    test_max_coins_example()
    test_max_coins_single()
    test_max_coins_empty()
    assert stdlib_only()
    print("memo-34 OK: burst-balloons")


if __name__ == "__main__":
    main()
