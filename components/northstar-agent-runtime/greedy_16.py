"""greedy_16: Best time to buy and sell stock II.

Capture every positive day-to-day price difference; it equals the optimal multi-trade profit.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_16_VERSION = "greedy-16.v1"


def max_profit_ii(prices):
    """Return the max profit with any number of buy/sell transactions."""
    return sum(max(0, b - a) for a, b in zip(prices, prices[1:]))

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
    assert max_profit_ii([7, 1, 5, 3, 6, 4]) == 7
    assert max_profit_ii([1, 2, 3, 4, 5]) == 4
    assert max_profit_ii([7, 6, 4, 3, 1]) == 0
    assert max_profit_ii([]) == 0
    assert stdlib_only()
    print("greedy_16 OK")


if __name__ == "__main__":
    main()
