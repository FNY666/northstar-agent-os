"""Backtracking: Subset sum -- find subset(s) of a list that add up to a target.

IS: exhaustive backtracking over subsets (each element used at most once),
duplicate-subset pruning via sorting, non-negative early cutoff.
IS NOT: unbounded knapsack (element reuse), approximate/DP-only solvers,
or the optimization variant (subset closest to target) -- this module only
answers exact-sum subset existence/enumeration.
"""

from __future__ import annotations

VERSION = "backtrack_41.v1"


import ast
from typing import List

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def subset_sum_all(nums: List[int], target: int) -> List[List[int]]:
    """Return every subset of nums (each element used at most once) summing to target."""
    results: List[List[int]] = []
    ordered = sorted(nums)
    nonneg = all(x >= 0 for x in ordered)

    def backtrack(start: int, path: List[int], total: int) -> None:
        if total == target:
            results.append(list(path))
            # A longer subset could still hit target via cancelling negatives,
            # so only prune the positive tail when everything is non-negative.
            if nonneg:
                return
        for i in range(start, len(ordered)):
            if i > start and ordered[i] == ordered[i - 1]:
                continue  # skip duplicate values to avoid duplicate subsets
            if nonneg and total + ordered[i] > target:
                break  # sorted: nothing later can fit either
            path.append(ordered[i])
            backtrack(i + 1, path, total + ordered[i])
            path.pop()

    backtrack(0, [], 0)
    return results


def find_subset(nums: List[int], target: int) -> List[int] | None:
    """Return one subset summing to target, or None if impossible."""
    found = subset_sum_all(nums, target)
    return found[0] if found else None


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
    assert subset_sum_all([2, 3, 5], 7) == [[2, 5]]
    assert subset_sum_all([1, 2, 3], 6) == [[1, 2, 3]]
    assert subset_sum_all([3, 34, 4, 12, 5, 2], 9) == [[2, 3, 4], [4, 5]]
    assert subset_sum_all([1, 2], 0) == [[]]
    assert find_subset([2, 3, 5], 7) == [2, 5]
    assert find_subset([1, 2], 7) is None
    print("backtrack_41 OK")


if __name__ == "__main__":
    main()
