"""dp-40: Burst balloons.

Max coins bursting balloons; bursting k last in (l, r) yields a[l]*a[k]*a[r] plus the optimal subintervals. Interval DP.

Time complexity: O(n^3) time
Space complexity: O(n^2) space
"""

import ast
import sys
from typing import List

DP_40_VERSION = "dp-40.v1"


def burst_balloons(nums: List[int]) -> int:
    """Return the maximum coins from bursting all balloons."""
    a = [1] + list(nums) + [1]
    n = len(a)
    dp = [[0] * n for _ in range(n)]
    for length in range(2, n):
        for l in range(n - length):
            r = l + length
            dp[l][r] = max(
                dp[l][k] + dp[k][r] + a[l] * a[k] * a[r]
                for k in range(l + 1, r)
            )
    return dp[0][n - 1]


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
    assert burst_balloons([3, 1, 5, 8]) == 167
    assert burst_balloons([1, 5]) == 10
    assert burst_balloons([]) == 0
    assert burst_balloons([7]) == 7
    assert burst_balloons([2, 2]) == 6
    assert stdlib_only()
    print("dp-40 OK")


if __name__ == "__main__":
    main()
