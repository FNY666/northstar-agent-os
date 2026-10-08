"""dp-23: Target sum (ways to assign signs).

Count ways to assign + / - to nums so they sum to target. Reduces to subset sum: choose a subset summing to (total+target)/2.

Time complexity: O(n * total) time
Space complexity: O(total) space
"""

import ast
import sys
from typing import List

DP_23_VERSION = "dp-23.v1"


def target_sum_ways(nums: List[int], target: int) -> int:
    """Return the number of sign assignments of nums summing to target."""
    total = sum(nums)
    if (total + target) % 2 or abs(target) > total:
        return 0
    s = (total + target) // 2
    dp = [0] * (s + 1)
    dp[0] = 1
    for x in nums:
        for t in range(s, x - 1, -1):
            dp[t] += dp[t - x]
    return dp[s]


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
    assert target_sum_ways([1, 1, 1, 1, 1], 3) == 5
    assert target_sum_ways([1], 1) == 1
    assert target_sum_ways([1, 2], 4) == 0
    assert target_sum_ways([1, 2, 3], 0) == 2
    assert target_sum_ways([], 0) == 1
    assert target_sum_ways([], 1) == 0
    assert stdlib_only()
    print("dp-23 OK")


if __name__ == "__main__":
    main()
