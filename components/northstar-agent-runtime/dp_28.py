"""dp-28: Best time to buy and sell stock with cooldown.

Max profit with unlimited trades but one cooldown day after each sale. Three rolling states: hold, sold, rest.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_28_VERSION = "dp-28.v1"


def max_profit_cooldown(prices: List[int]) -> int:
    """Return the max profit with a one-day cooldown after each sale."""
    hold = float("-inf")
    sold = 0
    rest = 0
    for p in prices:
        hold, sold, rest = max(hold, rest - p), hold + p, max(rest, sold)
    return max(sold, rest)


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
    assert max_profit_cooldown([1, 2, 3, 0, 2]) == 3
    assert max_profit_cooldown([1]) == 0
    assert max_profit_cooldown([]) == 0
    assert max_profit_cooldown([1, 2, 4]) == 3
    assert max_profit_cooldown([4, 3, 2, 1]) == 0
    assert stdlib_only()
    print("dp-28 OK")


if __name__ == "__main__":
    main()
