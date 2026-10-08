"""cc-01: Minimum coins (unbounded supply).

Classic coin change: fewest coins summing to amount with unlimited supply of each denomination. Returns -1 when impossible.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_01_VERSION = "cc-01.v1"


def _check(amount, coins):
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    return denoms


def min_coins(amount: int, coins: list) -> int:
    """Fewest coins summing to amount; -1 if impossible."""
    denoms = _check(amount, coins)
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
    assert min_coins(11, [1, 2, 5]) == 3
    assert min_coins(0, [1, 2, 5]) == 0
    assert min_coins(3, [2]) == -1
    assert min_coins(6, [1, 3, 4]) == 2
    try:
        min_coins(-1, [1, 2])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("cc-01 OK")


if __name__ == "__main__":
    main()
