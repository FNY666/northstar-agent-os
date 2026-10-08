"""cc-10: Count ways (0/1, each coin used at most once).

Count subsets of the given coins summing to amount.

Time complexity: O(amount * num_coins) time
Space complexity: O(amount)
"""

import ast
import sys

CC_10_VERSION = "cc-10.v1"


def count_ways_01(amount: int, coins: list) -> int:
    """Number of subsets of coins summing to amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if any(v <= 0 for v in coins):
        raise ValueError("coin values must be positive")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for v in coins:
        for i in range(amount, v - 1, -1):
            dp[i] += dp[i - v]
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
    assert count_ways_01(8, [1, 2, 5, 10]) == 1
    assert count_ways_01(3, [1, 2, 3]) == 2
    assert count_ways_01(0, [1]) == 1
    assert stdlib_only()
    print("cc-10 OK")


if __name__ == "__main__":
    main()
