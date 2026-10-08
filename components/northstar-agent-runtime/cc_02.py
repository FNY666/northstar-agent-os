"""cc-02: Count ways (combinations, order ignored).

Number of distinct combinations of coins summing to amount with unlimited supply. Coin order does not matter.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_02_VERSION = "cc-02.v1"


def count_ways(amount: int, coins: list) -> int:
    """Number of combinations summing to amount (order ignored)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d in denoms:
        for i in range(d, amount + 1):
            dp[i] += dp[i - d]
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
    assert count_ways(5, [1, 2, 5]) == 4
    assert count_ways(0, [1, 2]) == 1
    assert count_ways(3, [2]) == 0
    assert stdlib_only()
    print("cc-02 OK")


if __name__ == "__main__":
    main()
