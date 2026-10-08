"""Memoized Partition Equal Subset: memoization example.

Can nums split into two equal halves? Reduce to subset-sum target = total/2 with an (i, target) cache; odd totals fail fast.

What this IS: a real memoized subset-sum existence check with fail-fast on odd totals.
What this IS NOT: a partition reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_21_VERSION = "memo-partition-equal-subset.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-partition-equal-subset.v1"


class MemoError(Exception):
    """Fail-closed."""


def _can_reach(nums: tuple, target: int, i: int, _cache: dict) -> bool:
    key = (i, target)
    if key in _cache:
        return _cache[key]
    if target == 0:
        _cache[key] = True
    elif i >= len(nums) or target < 0:
        _cache[key] = False
    else:
        _cache[key] = _can_reach(nums, target - nums[i], i + 1, _cache) or _can_reach(nums, target, i + 1, _cache)
    return _cache[key]


def can_partition_equal(nums: tuple) -> bool:
    """True when nums split into two equal-sum halves."""
    total = sum(nums)
    if total % 2:
        return False
    return _can_reach(nums, total // 2, 0, {})

def test_can_partition_equal_true():
    assert can_partition_equal((1, 5, 11, 5)) is True


def test_can_partition_equal_odd():
    assert can_partition_equal((1, 2, 3, 5)) is False


def test_can_partition_equal_small():
    assert can_partition_equal((1, 1)) is True

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
    test_can_partition_equal_true()
    test_can_partition_equal_odd()
    test_can_partition_equal_small()
    assert stdlib_only()
    print("memo-21 OK: partition-equal-subset")


if __name__ == "__main__":
    main()
