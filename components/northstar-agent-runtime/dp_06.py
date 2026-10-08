"""dp-06: Coin change II (number of ways).

Count combinations making up amount (order of coins does not matter). Iterate coins outer, amounts inner.

Time complexity: O(amount * coins) time
Space complexity: O(amount) space
"""

import ast
import sys
from typing import List

DP_06_VERSION = "dp-06.v1"


def change_ways(coins: List[int], amount: int) -> int:
    """Return the number of coin combinations that make up amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for c in coins:
        for a in range(c, amount + 1):
            dp[a] += dp[a - c]
    return dp[amount]


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
    assert change_ways([1, 2, 5], 5) == 4
    assert change_ways([2], 3) == 0
    assert change_ways([1], 0) == 1
    assert change_ways([10], 10) == 1
    assert change_ways([], 0) == 1
    assert change_ways([], 3) == 0
    assert stdlib_only()
    print("dp-06 OK")


if __name__ == "__main__":
    main()
