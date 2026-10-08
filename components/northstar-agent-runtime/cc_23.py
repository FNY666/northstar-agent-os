"""cc-23: Feasibility via memoized recursion.

Top-down recursive reachability with lru_cache memoization.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

from functools import lru_cache

CC_23_VERSION = "cc-23.v1"


def can_make_change_memo(amount: int, coins: list) -> bool:
    """True when amount is formable (memoized recursion)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = tuple(sorted(set(coins)))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")

    @lru_cache(maxsize=None)
    def f(rem: int) -> bool:
        if rem == 0:
            return True
        if rem < 0:
            return False
        return any(f(rem - d) for d in denoms)

    return f(amount)

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
    assert can_make_change_memo(11, [1, 2, 5]) is True
    assert can_make_change_memo(3, [2, 4]) is False
    assert can_make_change_memo(0, [2]) is True
    assert stdlib_only()
    print("cc-23 OK")


if __name__ == "__main__":
    main()
