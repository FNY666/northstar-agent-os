"""cc-32: Square denominations.

Minimum-coin change over square denominations (Lagrange-flavored).

Time complexity: O(amount * sqrt(amount)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_32_VERSION = "cc-32.v1"


def square_denominations(limit: int) -> list:
    """Squares not exceeding limit."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    out = []
    i = 1
    while i * i <= limit:
        out.append(i * i)
        i += 1
    return out


def min_coins_squares(amount: int) -> int:
    """Fewest squares summing to amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = square_denominations(amount)
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
    assert square_denominations(10) == [1, 4, 9]
    assert min_coins_squares(12) == 3
    assert min_coins_squares(13) == 2
    assert stdlib_only()
    print("cc-32 OK")


if __name__ == "__main__":
    main()
