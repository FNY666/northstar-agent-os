"""cc-36: Minimum coins with mandatory denomination.

Fewest coins summing to amount under the constraint that at least one coin of a mandatory denomination is used.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_36_VERSION = "cc-36.v1"


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


def min_coins_mandatory(amount: int, coins: list, mandatory: int) -> int:
    """Min coins summing to amount including at least one mandatory coin."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if mandatory not in denoms:
        raise ValueError("mandatory denomination must be in coins")
    if amount < mandatory:
        return -1
    rest = _min_coins_dp(amount - mandatory, denoms)
    return rest + 1 if rest != -1 else -1

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
    assert min_coins_mandatory(11, [1, 2, 5], 5) == 3
    assert min_coins_mandatory(3, [1, 2, 5], 5) == -1
    assert min_coins_mandatory(10, [1, 2, 5], 2) == 4
    assert stdlib_only()
    print("cc-36 OK")


if __name__ == "__main__":
    main()
