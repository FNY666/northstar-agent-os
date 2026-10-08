"""cc-05: Count ways (bounded supply).

Number of combinations summing to amount when each denomination has a limited count.

Time complexity: O(amount * sum(count)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_05_VERSION = "cc-05.v1"


def count_ways_bounded(amount: int, coins: list) -> int:
    """Combinations summing to amount; coins is a list of (denomination, count)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    for d, c in coins:
        if d <= 0 or c < 0:
            raise ValueError("denominations positive, counts non-negative")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d, c in coins:
        new = [0] * (amount + 1)
        for i in range(amount + 1):
            total = 0
            for k in range(c + 1):
                if k * d > i:
                    break
                total += dp[i - k * d]
            new[i] = total
        dp = new
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
    assert count_ways_bounded(5, [(1, 5), (2, 2), (5, 1)]) == 4
    assert count_ways_bounded(4, [(2, 1)]) == 0
    assert count_ways_bounded(4, [(2, 2)]) == 1
    assert stdlib_only()
    print("cc-05 OK")


if __name__ == "__main__":
    main()
