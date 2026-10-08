"""cc-17: Minimum coins (no repeated denomination).

Each denomination may be used at most once, minimizing the coin count. Duplicate denominations in the input are merged.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_17_VERSION = "cc-17.v1"


def min_coins_no_repeat(amount: int, coins: list) -> int:
    """Fewest coins with each denomination used at most once."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if amount == 0:
        return 0
    INF = len(denoms) + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for d in denoms:
        for i in range(amount, d - 1, -1):
            if dp[i - d] + 1 < dp[i]:
                dp[i] = dp[i - d] + 1
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
    assert min_coins_no_repeat(6, [1, 5]) == 2
    assert min_coins_no_repeat(2, [1, 1, 5]) == -1
    assert min_coins_no_repeat(0, [1]) == 0
    assert stdlib_only()
    print("cc-17 OK")


if __name__ == "__main__":
    main()
