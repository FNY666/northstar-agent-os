"""dp-26: Best time to buy and sell stock (one trade).

Max profit from a single buy-then-sell. Track the lowest price seen so far and the best profit.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_26_VERSION = "dp-26.v1"


def max_profit_one(prices: List[int]) -> int:
    """Return the max profit from one buy/sell transaction."""
    low = float("inf")
    best = 0
    for p in prices:
        low = min(low, p)
        best = max(best, p - low)
    return best


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
    assert max_profit_one([7, 1, 5, 3, 6, 4]) == 5
    assert max_profit_one([7, 6, 4, 3, 1]) == 0
    assert max_profit_one([]) == 0
    assert max_profit_one([1]) == 0
    assert max_profit_one([1, 2, 3, 4, 5]) == 4
    assert stdlib_only()
    print("dp-26 OK")


if __name__ == "__main__":
    main()
