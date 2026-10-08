"""dp-44: Perfect squares (minimum count).

Fewest perfect squares summing to n (Lagrange). Unbounded-knapsack style DP over square denominations.

Time complexity: O(n sqrt n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_44_VERSION = "dp-44.v1"


def num_squares(n: int) -> int:
    """Return the fewest perfect squares summing to n."""
    if n < 0:
        raise ValueError("n must be non-negative")
    dp = list(range(n + 1))
    i = 1
    while i * i <= n:
        sq = i * i
        for j in range(sq, n + 1):
            dp[j] = min(dp[j], dp[j - sq] + 1)
        i += 1
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
    assert num_squares(12) == 3
    assert num_squares(13) == 2
    assert num_squares(1) == 1
    assert num_squares(0) == 0
    assert num_squares(4) == 1
    assert num_squares(43) == 3
    try:
        num_squares(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-44 OK")


if __name__ == "__main__":
    main()
