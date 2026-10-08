"""cc-12: Minimum cost (per-denomination cost).

Each denomination has its own per-use cost; minimize total cost instead of coin count.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_12_VERSION = "cc-12.v1"


def min_cost(amount: int, costs: dict):
    """Minimum total cost to reach amount; costs maps denomination -> cost."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if any(d <= 0 for d in costs):
        raise ValueError("denominations must be positive")
    denoms = sorted(costs)
    INF = float("inf")
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            c = dp[i - d] + costs[d]
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
    assert min_cost(11, {1: 1, 2: 1, 5: 1}) == 3
    assert min_cost(11, {1: 10, 5: 1}) == 12
    assert min_cost(3, {2: 5}) == -1
    assert stdlib_only()
    print("cc-12 OK")


if __name__ == "__main__":
    main()
