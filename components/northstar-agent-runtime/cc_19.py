"""cc-19: Minimum coins with parity constraint.

Fewest coins summing to amount whose coin count has the required parity (0 = even, 1 = odd).

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_19_VERSION = "cc-19.v1"


def min_coins_with_parity(amount: int, coins: list, parity: int) -> int:
    """Min coins with even (parity=0) or odd (parity=1) coin count."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if parity not in (0, 1):
        raise ValueError("parity must be 0 or 1")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    INF = amount + 1
    dp = [[INF, INF] for _ in range(amount + 1)]
    dp[0][0] = 0
    for i in range(1, amount + 1):
        for d in denoms:
            if d > i:
                break
            for p in (0, 1):
                if dp[i - d][p] != INF and dp[i - d][p] + 1 < dp[i][1 - p]:
                    dp[i][1 - p] = dp[i - d][p] + 1
    return dp[amount][parity] if dp[amount][parity] != INF else -1

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
    assert min_coins_with_parity(11, [1, 2, 5], 1) == 3
    assert min_coins_with_parity(10, [1, 2, 5], 0) == 2
    assert min_coins_with_parity(10, [1, 2, 5], 1) == 5
    assert stdlib_only()
    print("cc-19 OK")


if __name__ == "__main__":
    main()
