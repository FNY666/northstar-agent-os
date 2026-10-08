"""dac-07: Binary search (iterative).

Loop version of halving divide and conquer. O(log n), O(1) space.
"""
import ast
import sys

DAC_07_VERSION = "dac-07.v1"

def binary_search_iter(a, x):
    """Iterative binary search; index of *x* or -1."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == x:
            return mid
        if a[mid] < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert binary_search_iter([], 1) == -1
    assert binary_search_iter([2, 4, 6, 8], 6) == 2
    assert binary_search_iter([2, 4, 6, 8], 2) == 0
    assert binary_search_iter([2, 4, 6, 8], 8) == 3
    assert binary_search_iter([2, 4, 6, 8], 5) == -1
    assert stdlib_only()
    print("dac-07 OK")


if __name__ == "__main__":
    main()
