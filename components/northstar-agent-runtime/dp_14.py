"""dp-14: Matrix chain multiplication.

Minimum scalar multiplications parenthesizing a chain of matrices. dims[i] x dims[i+1] is matrix i; interval DP over chain length.

Time complexity: O(n^3) time
Space complexity: O(n^2) space
"""

import ast
import sys
from typing import List

DP_14_VERSION = "dp-14.v1"


def matrix_chain(dims: List[int]) -> int:
    """Return the minimum scalar multiplications for the matrix chain."""
    n = len(dims) - 1
    if n <= 1:
        return 0
    dp = [[0] * n for _ in range(n)]
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            dp[i][j] = min(
                dp[i][k] + dp[k + 1][j] + dims[i] * dims[k + 1] * dims[j + 1]
                for k in range(i, j)
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
    assert matrix_chain([1, 2, 3, 4]) == 18
    assert matrix_chain([40, 20, 30, 10, 30]) == 26000
    assert matrix_chain([10, 20]) == 0
    assert matrix_chain([10, 20, 30]) == 6000
    assert matrix_chain([10, 30, 5, 60]) == 4500
    assert stdlib_only()
    print("dp-14 OK")


if __name__ == "__main__":
    main()
