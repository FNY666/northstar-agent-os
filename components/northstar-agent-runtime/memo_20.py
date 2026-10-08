"""Memoized Target Sum Ways: memoization example.

Count sign assignments reaching a target: ways(i, t) = ways(i+1, t-nums[i]) + ways(i+1, t+nums[i]). The (i, target) cache prunes repeated states.

What this IS: a real memoized target-sum counter over an (index, target) cache.
What this IS NOT: a subset-sum existence check; the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_20_VERSION = "memo-target-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-target-sum.v1"


class MemoError(Exception):
    """Fail-closed."""


def target_sum_ways(nums: tuple, target: int, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized target-sum way counter."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, target)
    if key in cache:
        return cache[key]
    if i == len(nums):
        cache[key] = 1 if target == 0 else 0
    else:
        cache[key] = target_sum_ways(nums, target - nums[i], i + 1, cache) + target_sum_ways(
            nums, target + nums[i], i + 1, cache)
    return cache[key]

def test_target_sum_ways_example():
    assert target_sum_ways((1, 1, 1, 1, 1), 3) == 5


def test_target_sum_ways_zero():
    assert target_sum_ways((1,), 0) == 0


def test_target_sum_ways_empty():
    assert target_sum_ways((), 0) == 1

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
    test_target_sum_ways_example()
    test_target_sum_ways_zero()
    test_target_sum_ways_empty()
    assert stdlib_only()
    print("memo-20 OK: target-sum")


if __name__ == "__main__":
    main()
