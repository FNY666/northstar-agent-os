"""bs_23: Perfect square check

Decide whether a non-negative integer is a perfect square via
binary search.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_23_VERSION = "bs-23.v1"


def is_perfect_square(n):
    """Return True when n is a perfect square."""
    lo, hi = 0, n
    while lo <= hi:
        mid = (lo + hi) // 2
        sq = mid * mid
        if sq == n:
            return True
        if sq < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return False

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
    assert is_perfect_square(16) is True
    assert is_perfect_square(14) is False
    assert is_perfect_square(1) is True
    assert is_perfect_square(0) is True
    assert is_perfect_square(10**12) is True
    assert is_perfect_square(10**12 + 1) is False
    assert stdlib_only()
    print("bs_23 OK")


if __name__ == "__main__":
    main()
