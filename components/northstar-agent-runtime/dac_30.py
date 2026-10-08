"""dac-30: Exponential search.

Double the bound to find the range, then binary search inside. O(log i) for index i.
"""
import ast
import sys

DAC_30_VERSION = "dac-30.v1"

def _binary(a, x, lo, hi):
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == x:
            return mid
        if a[mid] < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def exponential_search(a, x):
    """Find range by doubling, then binary search."""
    n = len(a)
    if n == 0:
        return -1
    if a[0] == x:
        return 0
    bound = 1
    while bound < n and a[bound] < x:
        bound *= 2
    return _binary(a, x, bound // 2, min(bound, n - 1))

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
    assert exponential_search([], 1) == -1
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8], 1) == 0
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8], 8) == 7
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8], 5) == 4
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8], 9) == -1
    assert stdlib_only()
    print("dac-30 OK")


if __name__ == "__main__":
    main()
