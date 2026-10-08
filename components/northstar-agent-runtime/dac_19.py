"""dac-19: Search in rotated sorted array.

Halve the array; one half is always sorted, so we know where to recurse. O(log n).
"""
import ast
import sys

DAC_19_VERSION = "dac-19.v1"

def _sr(a, x, lo, hi):
    if lo > hi:
        return -1
    mid = (lo + hi) // 2
    if a[mid] == x:
        return mid
    if a[lo] <= a[mid]:
        if a[lo] <= x < a[mid]:
            return _sr(a, x, lo, mid - 1)
        return _sr(a, x, mid + 1, hi)
    if a[mid] < x <= a[hi]:
        return _sr(a, x, mid + 1, hi)
    return _sr(a, x, lo, mid - 1)


def search_rotated(a, x):
    """Binary search in a rotated sorted array; index or -1."""
    return _sr(list(a), x, 0, len(a) - 1)

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
    assert search_rotated([4, 5, 6, 7, 0, 1, 2], 0) == 4
    assert search_rotated([4, 5, 6, 7, 0, 1, 2], 3) == -1
    assert search_rotated([1, 2, 3, 4, 5], 3) == 2
    assert search_rotated([2, 1], 1) == 1
    assert search_rotated([], 1) == -1
    assert stdlib_only()
    print("dac-19 OK")


if __name__ == "__main__":
    main()
