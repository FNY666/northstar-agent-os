"""cc-50: Change-making summary.

One-call summary: feasibility, minimum coins and combination count for an amount.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_50_VERSION = "cc-50.v1"


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


def _count_ways_dp(amount, denoms):
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d in denoms:
        for i in range(d, amount + 1):
            dp[i] += dp[i - d]
    return dp[amount]


def change_summary(amount: int, coins: list) -> dict:
    """Dict with feasibility, min coins and combination count."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    mc = _min_coins_dp(amount, denoms)
    return {
        "amount": amount,
        "denominations": denoms,
        "feasible": mc != -1,
        "min_coins": mc,
        "num_ways": _count_ways_dp(amount, denoms),
    }

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
    s = change_summary(5, [1, 2, 5])
    assert s == {"amount": 5, "denominations": [1, 2, 5],
                 "feasible": True, "min_coins": 1, "num_ways": 4}
    s = change_summary(3, [2])
    assert s["feasible"] is False and s["min_coins"] == -1
    assert stdlib_only()
    print("cc-50 OK")


if __name__ == "__main__":
    main()
