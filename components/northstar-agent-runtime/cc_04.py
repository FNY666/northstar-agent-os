"""cc-04: Minimum coins (bounded supply).

Fewest coins summing to amount when each denomination has a limited count. Uses binary splitting to stay efficient.

Time complexity: O(amount * sum(log count)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_04_VERSION = "cc-04.v1"


def min_coins_bounded(amount: int, coins: list) -> int:
    """Fewest coins summing to amount; coins is a list of (denomination, count)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    for d, c in coins:
        if d <= 0 or c < 0:
            raise ValueError("denominations positive, counts non-negative")
    if amount == 0:
        return 0
    INF = amount + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for d, c in coins:
        k = 1
        while c > 0:
            take = min(k, c)
            v = take * d
            for i in range(amount, v - 1, -1):
                if dp[i - v] + take < dp[i]:
                    dp[i] = dp[i - v] + take
            c -= take
            k *= 2
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
    assert min_coins_bounded(11, [(5, 2), (2, 3), (1, 5)]) == 3
    assert min_coins_bounded(11, [(5, 1), (2, 1)]) == -1
    assert min_coins_bounded(0, [(5, 1)]) == 0
    assert stdlib_only()
    print("cc-04 OK")


if __name__ == "__main__":
    main()
