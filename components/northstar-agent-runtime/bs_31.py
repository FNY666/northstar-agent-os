"""bs_31: Search bitonic array

Search target in a bitonic array (increasing then decreasing)
by locating the peak and binary searching both sides.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_31_VERSION = "bs-31.v1"


def _bs_asc(a, target, lo, hi):
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return mid
        if a[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def _bs_desc(a, target, lo, hi):
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return mid
        if a[mid] > target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def search_bitonic(a, target):
    """Search target in a bitonic array; -1 when absent."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] < a[mid + 1]:
            lo = mid + 1
        else:
            hi = mid
    peak = lo
    i = _bs_asc(a, target, 0, peak)
    if i != -1:
        return i
    return _bs_desc(a, target, peak + 1, len(a) - 1)

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
    assert search_bitonic([1, 3, 8, 12, 4, 2], 8) == 2
    assert search_bitonic([1, 3, 8, 12, 4, 2], 4) == 4
    assert search_bitonic([1, 3, 8, 12, 4, 2], 2) == 5
    assert search_bitonic([1, 3, 8, 12, 4, 2], 7) == -1
    assert search_bitonic([1, 3, 8, 12, 4, 2], 12) == 3
    assert stdlib_only()
    print("bs_31 OK")


if __name__ == "__main__":
    main()
