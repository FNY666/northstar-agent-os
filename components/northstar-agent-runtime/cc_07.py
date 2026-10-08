"""cc-07: Feasibility (unbounded supply).

Boolean reachability: can the amount be formed at all.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_07_VERSION = "cc-07.v1"


def can_make_change(amount: int, coins: list) -> bool:
    """True when amount is formable with unlimited supply."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    reachable = [False] * (amount + 1)
    reachable[0] = True
    for i in range(1, amount + 1):
        for d in denoms:
            if d > i:
                break
            if reachable[i - d]:
                reachable[i] = True
                break
    return reachable[amount]

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
    assert can_make_change(11, [2, 5]) is True
    assert can_make_change(3, [2, 4]) is False
    assert can_make_change(0, [2, 4]) is True
    assert stdlib_only()
    print("cc-07 OK")


if __name__ == "__main__":
    main()
