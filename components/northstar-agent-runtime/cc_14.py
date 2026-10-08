"""cc-14: Maximum coins (unbounded supply).

Use as many coins as possible to sum to amount with unlimited supply. Returns -1 when impossible.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_14_VERSION = "cc-14.v1"


def max_coins(amount: int, coins: list) -> int:
    """Most coins summing to amount; -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    dp = [-1] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = -1
        for d in denoms:
            if d > i:
                break
            if dp[i - d] >= 0 and dp[i - d] + 1 > best:
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
    assert max_coins(11, [1, 2, 5]) == 11
    assert max_coins(3, [2]) == -1
    assert max_coins(0, [5]) == 0
    assert stdlib_only()
    print("cc-14 OK")


if __name__ == "__main__":
    main()
