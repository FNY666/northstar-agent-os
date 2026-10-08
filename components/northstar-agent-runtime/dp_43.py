"""dp-43: Partition to K equal-sum subsets.

Decide whether nums split into k subsets of equal sum. Bitmask memo DFS over subsets (small inputs).

Time complexity: O(k * 2^n) time (small n)
Space complexity: O(2^n) memo space
"""

import ast
import sys
from typing import List

DP_43_VERSION = "dp-43.v1"


def can_partition_k(nums: List[int], k: int) -> bool:
    """Return True when nums split into k equal-sum subsets."""
    from functools import lru_cache
    if not nums:
        return False
    total = sum(nums)
    if k <= 0 or total % k != 0:
        return False
    target = total // k
    items = tuple(sorted(nums, reverse=True))
    if items[0] > target:
        return False

    @lru_cache(maxsize=None)
    def dfs(mask: int, cur: int) -> bool:
        if mask == (1 << len(items)) - 1:
            return cur == 0
        for i in range(len(items)):
            if not (mask >> i) & 1 and cur + items[i] <= target:
                if dfs(mask | (1 << i), (cur + items[i]) % target):
                    return True
        return False

    return dfs(0, 0)


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert can_partition_k([4, 3, 2, 3, 5, 2, 1], 4) is True
    assert can_partition_k([1, 2, 3, 4], 3) is False
    assert can_partition_k([2, 2, 2, 2, 3, 3, 3, 3], 4) is True
    assert can_partition_k([1, 1, 1, 1], 2) is True
    assert can_partition_k([1, 2, 3], 0) is False
    assert can_partition_k([], 2) is False
    assert stdlib_only()
    print("dp-43 OK")


if __name__ == "__main__":
    main()
