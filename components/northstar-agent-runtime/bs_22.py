"""bs_22: Ceiling value

Smallest value >= target in a sorted list, or None when every
element is smaller.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_22_VERSION = "bs-22.v1"


def ceil_value(a, target):
    """Return the smallest a[i] >= target, or None."""
    lo, hi, ans = 0, len(a) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] >= target:
            ans = a[mid]
            hi = mid - 1
        else:
            lo = mid + 1
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
    assert ceil_value([1, 2, 8, 10], 5) == 8
    assert ceil_value([1, 2, 8, 10], 11) is None
    assert ceil_value([1, 2, 8, 10], 1) == 1
    assert ceil_value([1, 2, 8, 10], 2) == 2
    assert ceil_value([], 5) is None
    assert stdlib_only()
    print("bs_22 OK")


if __name__ == "__main__":
    main()
