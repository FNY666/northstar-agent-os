"""bs_24: First bad version

First version >= bad in a monotone badness predicate over
[1, n], the classic binary search on answer.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_24_VERSION = "bs-24.v1"


def first_bad(n, bad):
    """Return the first bad version in [1, n] given first bad == bad."""
    lo, hi = 1, n
    while lo < hi:
        mid = (lo + hi) // 2
        if mid >= bad:
            hi = mid
        else:
            lo = mid + 1
    return lo

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
    assert first_bad(5, 4) == 4
    assert first_bad(1, 1) == 1
    assert first_bad(10, 7) == 7
    assert first_bad(3, 1) == 1
    assert first_bad(100, 100) == 100
    assert stdlib_only()
    print("bs_24 OK")


if __name__ == "__main__":
    main()
