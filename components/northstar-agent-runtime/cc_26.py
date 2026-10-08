"""cc-26: Minimum coins under a weight budget.

Each denomination has a weight; minimize the coin count subject to the total weight not exceeding the budget.

Time complexity: O(amount * budget * num_denominations) time
Space complexity: O(amount * budget)
"""

import ast
import sys

CC_26_VERSION = "cc-26.v1"


def min_coins_weight_budget(amount: int, weights: dict, budget: int) -> int:
    """Min coins summing to amount with total weight <= budget."""
    if amount < 0 or budget < 0:
        raise ValueError("amount and budget must be non-negative")
    if any(d <= 0 for d in weights) or any(w < 0 for w in weights.values()):
        raise ValueError("denominations positive, weights non-negative")
    denoms = sorted(weights)
    INF = amount + 1
    dp = [[INF] * (budget + 1) for _ in range(amount + 1)]
    dp[0][0] = 0
    for i in range(amount + 1):
        for w in range(budget + 1):
            if dp[i][w] == INF:
                continue
            for d in denoms:
                ni, nw = i + d, w + weights[d]
                if ni <= amount and nw <= budget and dp[i][w] + 1 < dp[ni][nw]:
                    dp[ni][nw] = dp[i][w] + 1
    best = min(dp[amount])
    return best if best != INF else -1

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
    assert min_coins_weight_budget(11, {1: 1, 2: 3, 5: 2}, 6) == 3
    assert min_coins_weight_budget(11, {1: 1, 2: 3, 5: 2}, 4) == -1
    assert min_coins_weight_budget(0, {1: 1}, 0) == 0
    assert stdlib_only()
    print("cc-26 OK")


if __name__ == "__main__":
    main()
