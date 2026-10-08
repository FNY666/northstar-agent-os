"""cc-42: Count ways using at most m denominations.

Number of combinations summing to amount that use at most m distinct denominations.

Time complexity: O(amount * m * num_denominations) time
Space complexity: O(amount * m)
"""

import ast
import sys

CC_42_VERSION = "cc-42.v1"


def count_ways_at_most_m_denoms(amount: int, coins: list, m: int) -> int:
    """Combinations summing to amount using at most m distinct denominations."""
    if amount < 0 or m < 0:
        raise ValueError("amount and m must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    dp = [[0] * (m + 1) for _ in range(amount + 1)]
    dp[0][0] = 1
    for d in denoms:
        ndp = [row[:] for row in dp]
        for i in range(amount + 1):
            for k in range(m):
                s = 0
                t = 1
                while i - t * d >= 0:
                    s += dp[i - t * d][k]
                    t += 1
                ndp[i][k + 1] += s
        dp = ndp
    return sum(dp[amount][k] for k in range(m + 1))

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
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 1) == 2
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 2) == 4
    assert count_ways_at_most_m_denoms(0, [1, 2], 1) == 1
    assert stdlib_only()
    print("cc-42 OK")


if __name__ == "__main__":
    main()
