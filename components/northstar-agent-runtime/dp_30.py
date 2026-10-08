"""dp-30: Unique paths with obstacles.

Count right/down paths avoiding blocked cells (1 = obstacle). Blocked cells reset the rolling accumulator to zero.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_30_VERSION = "dp-30.v1"


def unique_paths_obstacles(grid: List[List[int]]) -> int:
    """Return the number of right/down paths avoiding obstacles."""
    if not grid or not grid[0]:
        return 0
    m, n = len(grid), len(grid[0])
    dp = [0] * n
    dp[0] = 1 if grid[0][0] == 0 else 0
    for i in range(m):
        for j in range(n):
            if grid[i][j] == 1:
                dp[j] = 0
            elif j > 0:
                dp[j] += dp[j - 1]
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
    assert unique_paths_obstacles([[0, 0, 0], [0, 1, 0], [0, 0, 0]]) == 2
    assert unique_paths_obstacles([[0, 1], [0, 0]]) == 1
    assert unique_paths_obstacles([[1]]) == 0
    assert unique_paths_obstacles([[0]]) == 1
    assert unique_paths_obstacles([]) == 0
    assert unique_paths_obstacles([[0, 0], [1, 1], [0, 0]]) == 0
    assert stdlib_only()
    print("dp-30 OK")


if __name__ == "__main__":
    main()
