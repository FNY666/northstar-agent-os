"""cc-45: Minimum coins using every denomination.

Fewest coins summing to amount under the constraint that every denomination is used at least once.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_45_VERSION = "cc-45.v1"


def _min_coins_dp(amount, denoms):
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


def min_coins_use_all(amount: int, coins: list) -> int:
    """Min coins using each denomination at least once; -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    base = sum(denoms)
    if amount < base:
        return -1
    rest = _min_coins_dp(amount - base, denoms)
    return rest + len(denoms) if rest != -1 else -1

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
    assert min_coins_use_all(11, [1, 2, 5]) == 5
    assert min_coins_use_all(7, [1, 2, 5]) == -1
    assert min_coins_use_all(8, [1, 2, 5]) == 3
    assert stdlib_only()
    print("cc-45 OK")


if __name__ == "__main__":
    main()
