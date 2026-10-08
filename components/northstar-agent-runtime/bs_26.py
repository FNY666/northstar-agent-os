"""bs_26: Rotation count

Number of rotations of a rotated sorted array, equal to the
index of its minimum element.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_26_VERSION = "bs-26.v1"


def rotation_count(a):
    """Return the rotation count of a rotated sorted array."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] > a[hi]:
            lo = mid + 1
        else:
            hi = mid
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
    assert rotation_count([15, 18, 2, 3, 6, 12]) == 2
    assert rotation_count([1, 2, 3]) == 0
    assert rotation_count([7, 9, 11, 12, 5]) == 4
    assert rotation_count([2, 1]) == 1
    assert rotation_count([1]) == 0
    assert stdlib_only()
    print("bs_26 OK")


if __name__ == "__main__":
    main()
