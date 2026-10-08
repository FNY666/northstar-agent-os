"""greedy_17: Best time to buy and sell stock I.

Track the lowest price seen so far and the best sell profit against it.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_17_VERSION = "greedy-17.v1"


def max_profit_i(prices):
    """Return the max profit of a single buy/sell transaction."""
    best = 0
    low = float("inf")
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
    assert max_profit_i([7, 1, 5, 3, 6, 4]) == 5
    assert max_profit_i([7, 6, 4, 3, 1]) == 0
    assert max_profit_i([]) == 0
    assert max_profit_i([2, 4, 1]) == 2
    assert stdlib_only()
    print("greedy_17 OK")


if __name__ == "__main__":
    main()
