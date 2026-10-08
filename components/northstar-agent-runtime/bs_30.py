"""bs_30: Search unknown-size array

Search a sorted array of unknown length through an accessor
that returns None past the end.

Time complexity: O(log i) time where i is the target index
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_30_VERSION = "bs-30.v1"


def make_get(arr):
    """Build an accessor returning None for out-of-range indices."""
    def get(i):
        return arr[i] if 0 <= i < len(arr) else None
    return get


def search_unknown_size(get, target):
    """Search target using get(i); get returns None past the end."""
    hi = 1
    while True:
        v = get(hi)
        if v is None or v >= target:
            break
        hi *= 2
    lo = hi // 2
    while lo <= hi:
        mid = (lo + hi) // 2
        v = get(mid)
        if v is None or v > target:
            hi = mid - 1
        elif v < target:
            lo = mid + 1
        else:
            return mid
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
    assert search_unknown_size(make_get([1, 3, 5, 7, 9, 11]), 7) == 3
    assert search_unknown_size(make_get([1, 3, 5, 7, 9, 11]), 1) == 0
    assert search_unknown_size(make_get([1, 3, 5, 7, 9, 11]), 11) == 5
    assert search_unknown_size(make_get([1, 3, 5, 7, 9, 11]), 8) == -1
    assert search_unknown_size(make_get([2]), 2) == 0
    assert stdlib_only()
    print("bs_30 OK")


if __name__ == "__main__":
    main()
