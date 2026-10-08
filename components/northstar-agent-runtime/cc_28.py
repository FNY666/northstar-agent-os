"""cc-28: Batch count ways.

Combination counts for many amounts at once, sharing one DP table.

Time complexity: O(max_amount * num_denominations) time
Space complexity: O(max_amount)
"""

import ast
import sys

CC_28_VERSION = "cc-28.v1"


def batch_count_ways(amounts: list, coins: list) -> list:
    """Combination count for each amount."""
    if any(a < 0 for a in amounts):
        raise ValueError("amounts must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if not amounts:
        return []
    top = max(amounts)
    dp = [0] * (top + 1)
    dp[0] = 1
    for d in denoms:
        for i in range(d, top + 1):
            dp[i] += dp[i - d]
    return [dp[a] for a in amounts]

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
    assert batch_count_ways([0, 5], [1, 2, 5]) == [1, 4]
    assert batch_count_ways([], [1]) == []
    assert batch_count_ways([3], [2]) == [0]
    assert stdlib_only()
    print("cc-28 OK")


if __name__ == "__main__":
    main()
