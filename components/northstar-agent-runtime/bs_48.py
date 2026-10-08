"""bs_48: Interpolation search

Probe positions by linear interpolation; excels on uniformly
distributed sorted data.

Time complexity: O(log log n) average, O(n) worst case
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_48_VERSION = "bs-48.v1"


def interpolation_search(a, target):
    """Return index of target in sorted list a, or -1."""
    lo, hi = 0, len(a) - 1
    while lo <= hi and a[lo] <= target <= a[hi]:
        if a[lo] == a[hi]:
            return lo if a[lo] == target else -1
        pos = lo + (target - a[lo]) * (hi - lo) // (a[hi] - a[lo])
        if a[pos] == target:
            return pos
        if a[pos] < target:
            lo = pos + 1
        else:
            hi = pos - 1
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
    assert interpolation_search([10, 20, 30, 40, 50], 30) == 2
    assert interpolation_search([10, 20, 30, 40, 50], 10) == 0
    assert interpolation_search([10, 20, 30, 40, 50], 60) == -1
    assert interpolation_search([5], 5) == 0
    assert interpolation_search([5], 3) == -1
    assert interpolation_search(list(range(0, 1000, 7)), 700) == 100
    assert stdlib_only()
    print("bs_48 OK")


if __name__ == "__main__":
    main()
