"""greedy_04: Minimum coins (canonical systems).

Greedy coin change: repeatedly take the largest denomination that fits.

Time complexity: O(d) time
Space complexity: O(d) auxiliary
"""

import ast
import sys
GREEDY_04_VERSION = "greedy-04.v1"


def min_coins(amount, coins=(25, 10, 5, 1)):
    """Return {denomination: count} making amount with fewest coins (greedy)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(coins, reverse=True)
    result = {}
    rest = amount
    for c in denoms:
        n, rest = divmod(rest, c)
        if n:
            result[c] = n
    if rest:
        raise ValueError("cannot make amount with given coins")
    return result

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
    assert min_coins(63) == {25: 2, 10: 1, 1: 3}
    assert min_coins(0) == {}
    assert min_coins(30, (10, 5, 1)) == {10: 3}
    try:
        min_coins(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("greedy_04 OK")


if __name__ == "__main__":
    main()
