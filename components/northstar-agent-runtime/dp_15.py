"""dp-15: Rod cutting.

Max revenue cutting a rod of length n given prices per length. dp[i] = max over first-cut j of prices[j-1] + dp[i-j].

Time complexity: O(n^2) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_15_VERSION = "dp-15.v1"


def rod_cut(prices: List[int], n: int) -> int:
    """Return the maximum revenue for a rod of length n."""
    if n < 0:
        raise ValueError("n must be non-negative")
    dp = [0] * (n + 1)
    for i in range(1, n + 1):
        best = 0
        for j in range(1, min(i, len(prices)) + 1):
            best = max(best, prices[j - 1] + dp[i - j])
        dp[i] = best
    return dp[n]


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
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 8) == 22
    assert rod_cut([3, 5, 8, 9, 10, 17, 17, 20], 8) == 24
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 0) == 0
    assert rod_cut([2], 3) == 6
    try:
        rod_cut([1], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-15 OK")


if __name__ == "__main__":
    main()
