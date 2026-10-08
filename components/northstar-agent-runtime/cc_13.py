"""cc-13: Minimum coins to reach at least target.

Overshoot is allowed: reach any amount >= target with the fewest coins, returning (count, amount_reached).

Time complexity: O((target + max_denom) * num_denominations) time
Space complexity: O(target + max_denom)
"""

import ast
import sys

CC_13_VERSION = "cc-13.v1"


def min_coins_at_least(target: int, coins: list):
    """Fewest coins reaching >= target; returns (count, amount_reached)."""
    if target < 0:
        raise ValueError("target must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if target == 0:
        return (0, 0)
    limit = target + max(denoms)
    INF = limit + 1
    dp = [INF] * (limit + 1)
    dp[0] = 0
    for i in range(1, limit + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            if dp[i - d] + 1 < best:
                best = dp[i - d] + 1
        dp[i] = best
    best = min(dp[target:])
    if best == INF:
        return (-1, -1)
    for i in range(target, limit + 1):
        if dp[i] == best:
            return (best, i)
    return (-1, -1)

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
    assert min_coins_at_least(11, [5, 10]) == (2, 15)
    assert min_coins_at_least(10, [5, 10]) == (1, 10)
    assert min_coins_at_least(0, [5]) == (0, 0)
    assert stdlib_only()
    print("cc-13 OK")


if __name__ == "__main__":
    main()
