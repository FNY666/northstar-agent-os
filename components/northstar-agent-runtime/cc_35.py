"""cc-35: Triangular denominations.

Minimum-coin change over triangular-number denominations.

Time complexity: O(amount * sqrt(amount)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_35_VERSION = "cc-35.v1"


def triangular_denominations(limit: int) -> list:
    """Triangular numbers not exceeding limit."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    out = []
    i, t = 1, 1
    while t <= limit:
        out.append(t)
        i += 1
        t = i * (i + 1) // 2
    return out


def min_coins_triangular(amount: int) -> int:
    """Fewest triangular numbers summing to amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = triangular_denominations(amount)
    if amount == 0:
        return 0
    INF = amount + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            if dp[i - d] + 1 < best:
                best = dp[i - d] + 1
        dp[i] = best
    return dp[amount]

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
    assert triangular_denominations(10) == [1, 3, 6, 10]
    assert min_coins_triangular(11) == 2
    assert min_coins_triangular(12) == 2
    assert stdlib_only()
    print("cc-35 OK")


if __name__ == "__main__":
    main()
