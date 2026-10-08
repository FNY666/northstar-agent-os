"""cc-20: Count ways modulo m.

Number of combinations summing to amount, computed modulo m.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_20_VERSION = "cc-20.v1"


def count_ways_mod(amount: int, coins: list, mod: int = 1000000007) -> int:
    """Combinations summing to amount, modulo mod."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if mod <= 0:
        raise ValueError("mod must be positive")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d in denoms:
        for i in range(d, amount + 1):
            dp[i] = (dp[i] + dp[i - d]) % mod
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
    assert count_ways_mod(5, [1, 2, 5]) == 4
    assert count_ways_mod(10, [1, 5], 100) == 3
    assert count_ways_mod(0, [1, 2], 7) == 1
    assert stdlib_only()
    print("cc-20 OK")


if __name__ == "__main__":
    main()
