"""dp-31: Minimum path sum in a grid.

Cheapest top-left to bottom-right path moving only right or down. One rolling row of running minima.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_31_VERSION = "dp-31.v1"


def min_path_sum(grid: List[List[int]]) -> int:
    """Return the minimum path sum moving only right or down."""
    if not grid or not grid[0]:
        raise ValueError("grid must be non-empty")
    m, n = len(grid), len(grid[0])
    dp = [0] * n
    for i in range(m):
        for j in range(n):
            if i == 0 and j == 0:
                dp[j] = grid[0][0]
            elif i == 0:
                dp[j] = dp[j - 1] + grid[i][j]
            elif j == 0:
                dp[j] = dp[j] + grid[i][j]
            else:
                dp[j] = min(dp[j], dp[j - 1]) + grid[i][j]
    return dp[n - 1]


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
    assert min_path_sum([[1, 3, 1], [1, 5, 1], [4, 2, 1]]) == 7
    assert min_path_sum([[1, 2, 3], [4, 5, 6]]) == 12
    assert min_path_sum([[5]]) == 5
    assert min_path_sum([[1, 2], [1, 1]]) == 3
    try:
        min_path_sum([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-31 OK")


if __name__ == "__main__":
    main()
