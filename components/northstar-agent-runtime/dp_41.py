"""dp-41: Stone game (optimal play).

Two players alternately take an end pile; both play optimally. dp[l][r] is the current player's net advantage on piles[l:r+1].

Time complexity: O(n^2) time
Space complexity: O(n^2) space
"""

import ast
import sys
from typing import List

DP_41_VERSION = "dp-41.v1"


def stone_game(piles: List[int]) -> bool:
    """Return True when the first player wins with optimal play."""
    n = len(piles)
    if n == 0:
        return False
    dp = [[0] * n for _ in range(n)]
    for i in range(n):
        dp[i][i] = piles[i]
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            dp[i][j] = max(piles[i] - dp[i + 1][j], piles[j] - dp[i][j - 1])
    return dp[0][n - 1] > 0


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
    assert stone_game([5, 3, 4, 5]) is True
    assert stone_game([3, 7, 2, 3]) is True
    assert stone_game([1, 2]) is True
    assert stone_game([2, 1]) is True
    assert stone_game([]) is False
    assert stone_game([1, 100, 3]) is False
    assert stdlib_only()
    print("dp-41 OK")


if __name__ == "__main__":
    main()
