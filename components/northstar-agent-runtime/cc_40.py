"""cc-40: Minimum-coins table.

Build the full minimum-coin table for every amount from 0 to limit in one DP pass.

Time complexity: O(limit * num_denominations) time
Space complexity: O(limit)
"""

import ast
import sys

CC_40_VERSION = "cc-40.v1"


def min_coins_table(limit: int, coins: list) -> list:
    """Min-coin count for every amount in [0, limit]; -1 where impossible."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
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
    return [v if v != INF else -1 for v in dp]

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
    assert min_coins_table(6, [1, 3, 4]) == [0, 1, 2, 1, 1, 2, 2]
    assert min_coins_table(0, [5]) == [0]
    assert min_coins_table(3, [2]) == [0, -1, 1, -1]
    assert stdlib_only()
    print("cc-40 OK")


if __name__ == "__main__":
    main()
