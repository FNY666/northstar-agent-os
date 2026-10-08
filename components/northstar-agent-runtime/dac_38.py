"""dac-38: Floor and ceil in sorted array.

Two biased binary searches: greatest <= x and smallest >= x. O(log n).
"""
import ast
import sys

DAC_38_VERSION = "dac-38.v1"

def _floor(a, x, lo, hi):
    if lo > hi:
        return -1
    mid = (lo + hi) // 2
    if a[mid] == x:
        return mid
    if a[mid] < x:
        r = _floor(a, x, mid + 1, hi)
        return r if r != -1 else mid
    return _floor(a, x, lo, mid - 1)


def _ceil(a, x, lo, hi):
    if lo > hi:
        return -1
    mid = (lo + hi) // 2
    if a[mid] == x:
        return mid
    if a[mid] > x:
        r = _ceil(a, x, lo, mid - 1)
        return r if r != -1 else mid
    return _ceil(a, x, mid + 1, hi)


def floor_ceil(a, x):
    """(floor_index, ceil_index) of x in sorted a; -1 when none exists."""
    a = list(a)
    return (_floor(a, x, 0, len(a) - 1), _ceil(a, x, 0, len(a) - 1))

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
    assert floor_ceil([1, 2, 4, 6, 8], 5) == (2, 3)
    assert floor_ceil([1, 2, 4, 6, 8], 4) == (2, 2)
    assert floor_ceil([1, 2, 4, 6, 8], 0) == (-1, 0)
    assert floor_ceil([1, 2, 4, 6, 8], 9) == (4, -1)
    assert floor_ceil([], 3) == (-1, -1)
    assert stdlib_only()
    print("dac-38 OK")


if __name__ == "__main__":
    main()
