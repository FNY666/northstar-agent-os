"""bs_50: Binary search with key function

Binary search over a list of records sorted by a key function,
matching on the extracted key.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_50_VERSION = "bs-50.v1"


def binary_search_key(a, target, key):
    """Return index of the record whose key equals target, or -1."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        v = key(a[mid])
        if v == target:
            return mid
        if v < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

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
    assert binary_search_key([("a", 1), ("b", 3), ("c", 5)], 3, key=lambda t: t[1]) == 1
    assert binary_search_key([("a", 1), ("b", 3), ("c", 5)], 5, key=lambda t: t[1]) == 2
    assert binary_search_key([("a", 1), ("b", 3), ("c", 5)], 4, key=lambda t: t[1]) == -1
    assert binary_search_key([], 1, key=lambda x: x) == -1
    assert binary_search_key([("z", 9)], 9, key=lambda t: t[1]) == 0
    assert stdlib_only()
    print("bs_50 OK")


if __name__ == "__main__":
    main()
