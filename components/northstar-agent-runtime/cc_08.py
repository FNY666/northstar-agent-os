"""cc-08: Feasibility (bounded supply).

Boolean reachability with limited counts per denomination.

Time complexity: O(amount * sum(count)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_08_VERSION = "cc-08.v1"


def can_make_change_bounded(amount: int, coins: list) -> bool:
    """True when amount is formable; coins is a list of (denomination, count)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    for d, c in coins:
        if d <= 0 or c < 0:
            raise ValueError("denominations positive, counts non-negative")
    reachable = [False] * (amount + 1)
    reachable[0] = True
    for d, c in coins:
        new = reachable[:]
        for i in range(amount + 1):
            if reachable[i]:
                for k in range(1, c + 1):
                    if i + k * d > amount:
                        break
                    new[i + k * d] = True
        reachable = new
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
    assert can_make_change_bounded(7, [(5, 1), (2, 1)]) is True
    assert can_make_change_bounded(7, [(5, 1)]) is False
    assert can_make_change_bounded(0, [(5, 1)]) is True
    assert stdlib_only()
    print("cc-08 OK")


if __name__ == "__main__":
    main()
