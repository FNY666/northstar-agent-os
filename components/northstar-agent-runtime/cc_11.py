"""cc-11: Minimum coins with reconstruction.

Fewest coins summing to amount, returning both the count and the actual coins used (sorted ascending).

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_11_VERSION = "cc-11.v1"


def min_coins_with_change(amount: int, coins: list):
    """Return (min_count, sorted coin list); (-1, []) when impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    INF = amount + 1
    dp = [INF] * (amount + 1)
    prev = [-1] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        for d in denoms:
            if d > i:
                break
            if dp[i - d] + 1 < dp[i]:
                dp[i] = dp[i - d] + 1
                prev[i] = d
    if dp[amount] == INF:
        return (-1, [])
    out = []
    cur = amount
    while cur > 0:
        out.append(prev[cur])
        cur -= prev[cur]
    return (dp[amount], sorted(out))

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
    assert min_coins_with_change(11, [1, 2, 5]) == (3, [1, 5, 5])
    assert min_coins_with_change(3, [2]) == (-1, [])
    assert min_coins_with_change(0, [1, 2]) == (0, [])
    assert stdlib_only()
    print("cc-11 OK")


if __name__ == "__main__":
    main()
