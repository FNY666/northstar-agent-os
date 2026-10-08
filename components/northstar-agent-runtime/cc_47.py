"""cc-47: Minimum coins with exactly one large coin.

Fewest coins summing to amount using exactly one coin above a threshold.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_47_VERSION = "cc-47.v1"


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


def min_coins_one_large(amount: int, coins: list, threshold: int) -> int:
    """Min coins with exactly one coin above threshold; -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    large = [d for d in denoms if d > threshold]
    best = None
    for d in large:
        if d > amount:
            continue
        rest = _min_coins_dp(amount - d, denoms)
        if rest != -1:
            total = rest + 1
            if best is None or total < best:
                best = total
    return best if best is not None else -1

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
    assert min_coins_one_large(11, [1, 2, 5], 2) == 3
    assert min_coins_one_large(4, [1, 2, 5], 2) == -1
    assert min_coins_one_large(10, [1, 2, 5], 4) == 2
    assert stdlib_only()
    print("cc-47 OK")


if __name__ == "__main__":
    main()
