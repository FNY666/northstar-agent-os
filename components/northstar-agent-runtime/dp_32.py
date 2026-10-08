"""dp-32: Triangle minimum path.

Cheapest top-to-bottom path in a triangle, moving to adjacent numbers below. Bottom-up collapse into one row.

Time complexity: O(n^2) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_32_VERSION = "dp-32.v1"


def triangle_min(triangle: List[List[int]]) -> int:
    """Return the minimum path sum from top to bottom of the triangle."""
    if not triangle:
        raise ValueError("triangle must be non-empty")
    dp = list(triangle[-1])
    for row in reversed(triangle[:-1]):
        dp = [row[i] + min(dp[i], dp[i + 1]) for i in range(len(row))]
    return dp[0]


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
    assert triangle_min([[2], [3, 4], [6, 5, 7], [4, 1, 8, 3]]) == 11
    assert triangle_min([[-10]]) == -10
    assert triangle_min([[1], [2, 3]]) == 3
    assert triangle_min([[-1], [2, 3], [1, -1, -3]]) == -1
    try:
        triangle_min([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-32 OK")


if __name__ == "__main__":
    main()
