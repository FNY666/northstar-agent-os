"""bs_21: Floor value

Largest value <= target in a sorted list, or None when every
element is greater.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_21_VERSION = "bs-21.v1"


def floor_value(a, target):
    """Return the greatest a[i] <= target, or None."""
    lo, hi, ans = 0, len(a) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] <= target:
            ans = a[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return ans

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
    assert floor_value([1, 2, 8, 10], 5) == 2
    assert floor_value([1, 2, 8, 10], 0) is None
    assert floor_value([1, 2, 8, 10], 10) == 10
    assert floor_value([1, 2, 8, 10], 8) == 8
    assert floor_value([], 5) is None
    assert stdlib_only()
    print("bs_21 OK")


if __name__ == "__main__":
    main()
