"""dp-48: Maximal square.

Area of the largest all-'1' square in a binary matrix. dp cell = 1 + min of top/left/diagonal when the cell is '1'.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_48_VERSION = "dp-48.v1"


def maximal_square(matrix: List[List[str]]) -> int:
    """Return the area of the largest square of '1's."""
    if not matrix or not matrix[0]:
        return 0
    m, n = len(matrix), len(matrix[0])
    dp = [0] * (n + 1)
    best = 0
    for i in range(m):
        prev = 0
        for j in range(n):
            tmp = dp[j + 1]
            if matrix[i][j] == "1":
                dp[j + 1] = min(dp[j], dp[j + 1], prev) + 1
                best = max(best, dp[j + 1])
            else:
                dp[j + 1] = 0
            prev = tmp
    return best * best


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
    assert maximal_square([["1", "0", "1", "0", "0"],
                             ["1", "0", "1", "1", "1"],
                             ["1", "1", "1", "1", "1"],
                             ["1", "0", "0", "1", "0"]]) == 4
    assert maximal_square([["0"]]) == 0
    assert maximal_square([["1"]]) == 1
    assert maximal_square([]) == 0
    assert maximal_square([["1", "1"], ["1", "1"]]) == 4
    assert maximal_square([["0", "1"], ["1", "0"]]) == 1
    assert stdlib_only()
    print("dp-48 OK")


if __name__ == "__main__":
    main()
