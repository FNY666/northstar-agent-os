"""cc-24: Count ways via memoized recursion.

Top-down recursive combination counting with lru_cache.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount * num_denominations)
"""

import ast
import sys

from functools import lru_cache

CC_24_VERSION = "cc-24.v1"


def count_ways_memo(amount: int, coins: list) -> int:
    """Combinations summing to amount (memoized recursion)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = tuple(sorted(set(coins)))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")

    @lru_cache(maxsize=None)
    def f(rem: int, idx: int) -> int:
        if rem == 0:
            return 1
        if rem < 0 or idx >= len(denoms):
            return 0
        return f(rem, idx + 1) + f(rem - denoms[idx], idx)

    return f(amount, 0)

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
    assert count_ways_memo(5, [1, 2, 5]) == 4
    assert count_ways_memo(0, [1, 2]) == 1
    assert count_ways_memo(3, [2]) == 0
    assert stdlib_only()
    print("cc-24 OK")


if __name__ == "__main__":
    main()
