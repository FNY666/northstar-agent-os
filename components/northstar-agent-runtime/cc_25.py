"""cc-25: Robust min coins (worst single-denomination removal).

Worst-case fewest coins after an adversary removes one denomination; -1 if any removal makes the amount impossible.

Time complexity: O(num_denominations * amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_25_VERSION = "cc-25.v1"


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


def min_coins_robust(amount: int, coins: list) -> int:
    """Worst-case min coins over removing each single denomination."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if amount == 0:
        return 0
    worst = -1
    for skip in denoms:
        rest = [d for d in denoms if d != skip]
        v = _min_coins_dp(amount, rest)
        if v == -1:
            return -1
        worst = max(worst, v)
    return worst

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
    assert min_coins_robust(11, [1, 2, 5]) == 6
    assert min_coins_robust(10, [1, 2, 5]) == 5
    assert min_coins_robust(0, [1, 2]) == 0
    assert stdlib_only()
    print("cc-25 OK")


if __name__ == "__main__":
    main()
