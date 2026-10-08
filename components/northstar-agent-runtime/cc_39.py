"""cc-39: Minimum coins with large-denomination penalty.

Minimize coins + penalty * (coins above a threshold), trading off few large coins against many small ones.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_39_VERSION = "cc-39.v1"


def min_coins_penalty(amount: int, coins: list, threshold: int, penalty: int):
    """Minimize coin count plus penalty per coin above threshold."""
    if amount < 0 or penalty < 0:
        raise ValueError("amount and penalty must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    INF = float("inf")
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            c = dp[i - d] + 1 + (penalty if d > threshold else 0)
            if c < best:
                best = c
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
    assert min_coins_penalty(11, [1, 2, 5], 2, 10) == 11
    assert min_coins_penalty(10, [1, 2, 5], 2, 10) == 10
    assert min_coins_penalty(11, [1, 2, 5], 2, 0) == 3
    assert stdlib_only()
    print("cc-39 OK")


if __name__ == "__main__":
    main()
