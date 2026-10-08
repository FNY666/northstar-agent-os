"""bs_17: Integer square root

Floor of the square root of a non-negative integer via binary
search.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_17_VERSION = "bs-17.v1"


def isqrt(n):
    """Return floor(sqrt(n)) for n >= 0."""
    lo, hi = 0, n
    while lo <= hi:
        mid = (lo + hi) // 2
        if mid * mid <= n:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi

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
    assert isqrt(8) == 2
    assert isqrt(16) == 4
    assert isqrt(0) == 0
    assert isqrt(1) == 1
    assert isqrt(15) == 3
    assert isqrt(10**12) == 10**6
    assert stdlib_only()
    print("bs_17 OK")


if __name__ == "__main__":
    main()
