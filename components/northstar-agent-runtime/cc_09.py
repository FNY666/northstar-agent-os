"""cc-09: Minimum coins (0/1, each coin used at most once).

Each coin instance may be used at most once; minimize the number of coins summing to amount.

Time complexity: O(amount * num_coins) time
Space complexity: O(amount)
"""

import ast
import sys

CC_09_VERSION = "cc-09.v1"


def min_coins_01(amount: int, coins: list) -> int:
    """Fewest coins summing to amount, each coin usable at most once."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if any(v <= 0 for v in coins):
        raise ValueError("coin values must be positive")
    if amount == 0:
        return 0
    INF = len(coins) + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for v in coins:
        for i in range(amount, v - 1, -1):
            if dp[i - v] + 1 < dp[i]:
                dp[i] = dp[i - v] + 1
    return dp[amount] if dp[amount] != INF else -1

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
    assert min_coins_01(8, [1, 2, 5, 10]) == 3
    assert min_coins_01(9, [1, 2, 5, 10]) == -1
    assert min_coins_01(0, [5]) == 0
    assert stdlib_only()
    print("cc-09 OK")


if __name__ == "__main__":
    main()
