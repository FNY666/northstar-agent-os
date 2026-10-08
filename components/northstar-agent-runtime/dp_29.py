"""dp-29: Unique paths in a grid.

Count paths from top-left to bottom-right moving only right or down. One rolling row of binomial-style accumulation.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_29_VERSION = "dp-29.v1"


def unique_paths(m: int, n: int) -> int:
    """Return the number of right/down paths in an m x n grid."""
    if m <= 0 or n <= 0:
        raise ValueError("m and n must be positive")
    dp = [1] * n
    for _ in range(1, m):
        for j in range(1, n):
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
    assert unique_paths(3, 7) == 28
    assert unique_paths(3, 2) == 3
    assert unique_paths(1, 1) == 1
    assert unique_paths(1, 5) == 1
    assert unique_paths(7, 3) == 28
    try:
        unique_paths(0, 3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-29 OK")


if __name__ == "__main__":
    main()
