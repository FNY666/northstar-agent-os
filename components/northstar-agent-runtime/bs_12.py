"""bs_12: Find peak element

Return an index i where a[i] is strictly greater than its
neighbours (edges compare against one neighbour).

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_12_VERSION = "bs-12.v1"


def find_peak(a):
    """Return the index of any peak element."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] > a[mid + 1]:
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
    assert find_peak([1, 2, 3, 1]) == 2
    assert find_peak([1, 2, 1, 3, 5, 6, 4]) == 5
    assert find_peak([1]) == 0
    assert find_peak([3, 2, 1]) == 0
    assert find_peak([1, 2, 3, 4]) == 3
    assert stdlib_only()
    print("bs_12 OK")


if __name__ == "__main__":
    main()
