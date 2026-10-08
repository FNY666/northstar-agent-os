"""Backtracking: partition a multiset into k equal-sum subsets.

IS: decides whether the numbers can be split into k non-empty groups
with identical sums, via descending-order bucket backtracking with
duplicate-bucket pruning. IS NOT: a subset enumerator - it returns a
boolean only, not the actual partition; and it is exponential in the
worst case, so it is meant for small inputs, not production scheduling.
"""

import ast
from typing import List, Optional

VERSION = "backtrack_23.v1"


def can_partition_k_subsets(nums: List[int], k: int) -> bool:
    """True iff nums can be split into k groups with equal sums."""
    if k <= 0 or not nums:
        return False
    total = sum(nums)
    if total % k != 0:
        return False
    target = total // k
    order = sorted(nums, reverse=True)
    if order[0] > target:
        return False
    buckets = [0] * k

    def dfs(i: int) -> bool:
        if i == len(order):
            return all(b == target for b in buckets)
        v = order[i]
        seen = set()
        for j in range(k):
            if buckets[j] + v > target:
                continue
            if buckets[j] in seen:
                continue
            seen.add(buckets[j])
            buckets[j] += v
            if dfs(i + 1):
                return True
            buckets[j] -= v
            if buckets[j] == 0:
                break
        return False

    return dfs(0)


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert can_partition_k_subsets([4, 3, 2, 3, 5, 2, 1], 4) is True
    assert can_partition_k_subsets([1, 2, 3, 4], 3) is False
    assert can_partition_k_subsets([2, 2, 2, 2, 3, 3, 3, 3], 4) is True
    assert can_partition_k_subsets([1], 1) is True
    assert can_partition_k_subsets([10, 1, 1], 2) is False
    print("backtrack_23 OK")


if __name__ == "__main__":
    main()
