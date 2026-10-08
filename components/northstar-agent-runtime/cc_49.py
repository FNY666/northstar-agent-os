"""cc-49: Greedy-vs-optimal gap.

How many extra coins greedy uses over the optimum for an amount; None when either method cannot form the amount.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_49_VERSION = "cc-49.v1"


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


def _greedy_count(amount, denoms):
    rem = amount
    count = 0
    for d in sorted(denoms, reverse=True):
        count += rem // d
        rem %= d
    return count if rem == 0 else -1


def greedy_optimal_gap(amount: int, coins: list):
    """greedy_count - optimal_count, or None when either fails."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    g = _greedy_count(amount, denoms)
    o = _min_coins_dp(amount, denoms)
    if g == -1 or o == -1:
        return None
    return g - o

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
    assert greedy_optimal_gap(6, [1, 3, 4]) == 1
    assert greedy_optimal_gap(11, [1, 2, 5]) == 0
    assert greedy_optimal_gap(3, [2, 4]) is None
    assert stdlib_only()
    print("cc-49 OK")


if __name__ == "__main__":
    main()
