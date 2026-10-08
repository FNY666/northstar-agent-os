"""cc-27: Batch minimum coins.

Minimum-coin answers for many amounts at once, sharing one DP table built up to the largest amount.

Time complexity: O(max_amount * num_denominations) time
Space complexity: O(max_amount)
"""

import ast
import sys

CC_27_VERSION = "cc-27.v1"


def batch_min_coins(amounts: list, coins: list) -> list:
    """Min-coin count for each amount; -1 where impossible."""
    if any(a < 0 for a in amounts):
        raise ValueError("amounts must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if not amounts:
        return []
    top = max(amounts)
    INF = top + 1
    dp = [INF] * (top + 1)
    dp[0] = 0
    for i in range(1, top + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            if dp[i - d] + 1 < best:
                best = dp[i - d] + 1
        dp[i] = best
    return [dp[a] if dp[a] != INF else -1 for a in amounts]

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
    assert batch_min_coins([0, 1, 11, 3], [1, 2, 5]) == [0, 1, 3, 2]
    assert batch_min_coins([], [1, 2]) == []
    assert batch_min_coins([3], [2]) == [-1]
    assert stdlib_only()
    print("cc-27 OK")


if __name__ == "__main__":
    main()
