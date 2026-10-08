"""Backtracking: Partition equal subset sum -- decide if a list splits into two
subsets with equal sum.

IS: backtracking search for a subset summing to total/2, with descending
order, duplicate-value skipping, and overshoot pruning.
IS NOT: the k-partition generalization, the enumeration of all partitions,
or a bitset/DP optimizer -- this module answers the boolean decision only.
"""

from __future__ import annotations

VERSION = "backtrack_42.v1"


import ast
from typing import List

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def can_partition(nums: List[int]) -> bool:
    """Return True iff nums can be split into two subsets of equal sum."""
    total = sum(nums)
    if total % 2 != 0:
        return False
    target = total // 2
    ordered = sorted(nums, reverse=True)

    def backtrack(i: int, remaining: int) -> bool:
        if remaining == 0:
            return True
        if i == len(ordered) or remaining < 0:
            return False
        for j in range(i, len(ordered)):
            if j > i and ordered[j] == ordered[j - 1]:
                continue  # skip duplicate values
            if ordered[j] > remaining:
                continue  # overshoot: cannot be in this subset
            if backtrack(j + 1, remaining - ordered[j]):
                return True
        return False

    return backtrack(0, target)


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert can_partition([1, 5, 11, 5]) is True
    assert can_partition([1, 2, 3, 5]) is False
    assert can_partition([2, 2]) is True
    assert can_partition([1, 1, 1, 1]) is True
    assert can_partition([1, 2, 5]) is False  # odd total
    assert can_partition([]) is True  # two empty subsets
    print("backtrack_42 OK")


if __name__ == "__main__":
    main()
