"""dp-49: Dungeon game (minimum HP).

Minimum initial health to survive a dungeon of damage/healing cells. Backward DP: need at least 1 HP entering every cell.

Time complexity: O(m*n) time
Space complexity: O(m*n) space
"""

import ast
import sys
from typing import List

DP_49_VERSION = "dp-49.v1"


def dungeon(hp: List[List[int]]) -> int:
    """Return the minimum initial health to reach the bottom-right alive."""
    if not hp or not hp[0]:
        raise ValueError("dungeon must be non-empty")
    m, n = len(hp), len(hp[0])
    dp = [[0] * n for _ in range(m)]
    dp[m - 1][n - 1] = max(1, 1 - hp[m - 1][n - 1])
    for i in range(m - 2, -1, -1):
        dp[i][n - 1] = max(1, dp[i + 1][n - 1] - hp[i][n - 1])
    for j in range(n - 2, -1, -1):
        dp[m - 1][j] = max(1, dp[m - 1][j + 1] - hp[m - 1][j])
    for i in range(m - 2, -1, -1):
        for j in range(n - 2, -1, -1):
            dp[i][j] = max(1, min(dp[i + 1][j], dp[i][j + 1]) - hp[i][j])
    return dp[0][0]


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
    assert dungeon([[-2, -3, 3], [-5, -10, 1], [10, 30, -5]]) == 7
    assert dungeon([[0]]) == 1
    assert dungeon([[5]]) == 1
    assert dungeon([[-3]]) == 4
    assert dungeon([[1, -3, 3], [0, -2, 0], [-3, -3, -3]]) == 3
    try:
        dungeon([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-49 OK")


if __name__ == "__main__":
    main()
