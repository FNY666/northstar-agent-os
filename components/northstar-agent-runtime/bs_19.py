"""bs_19: Integer nth root

Floor of the kth root of a non-negative integer via binary
search.

Time complexity: O(k log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_19_VERSION = "bs-19.v1"


def iroot(n, k):
    """Return floor(n ** (1/k)) for n >= 0, k >= 1."""
    lo, hi = 0, n
    while lo <= hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
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
    assert iroot(27, 3) == 3
    assert iroot(28, 3) == 3
    assert iroot(16, 2) == 4
    assert iroot(100, 3) == 4
    assert iroot(1, 5) == 1
    assert iroot(0, 2) == 0
    assert stdlib_only()
    print("bs_19 OK")


if __name__ == "__main__":
    main()
