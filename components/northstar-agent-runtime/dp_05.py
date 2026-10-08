"""dp-05: Coin change (minimum coins).

Fewest coins making up amount; -1 when impossible. dp[a] = min over coins c of dp[a-c] + 1.

Time complexity: O(amount * coins) time
Space complexity: O(amount) space
"""

import ast
import sys
from typing import List

DP_05_VERSION = "dp-05.v1"


def coin_change(coins: List[int], amount: int) -> int:
    """Return the fewest coins needed for amount, or -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    INF = amount + 1
    dp = [0] + [INF] * amount
    for a in range(1, amount + 1):
        for c in coins:
            if c <= a:
                dp[a] = min(dp[a], dp[a - c] + 1)
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
    assert coin_change([1, 2, 5], 11) == 3
    assert coin_change([2], 3) == -1
    assert coin_change([1], 0) == 0
    assert coin_change([1, 2, 5], 0) == 0
    assert coin_change([186, 419, 83, 408], 6249) == 20
    try:
        coin_change([1], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-05 OK")


if __name__ == "__main__":
    main()
