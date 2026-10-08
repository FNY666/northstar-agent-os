"""bs_33: Kth element of two sorted arrays

Kth smallest element (1-indexed) of the union of two sorted
arrays via binary search on the partition point.

Time complexity: O(log(min(m, n))) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_33_VERSION = "bs-33.v1"


def kth_two_sorted(a, b, k):
    """Return the kth smallest element (1-indexed) of two sorted arrays."""
    if len(a) > len(b):
        a, b = b, a
    m, n = len(a), len(b)
    lo, hi = max(0, k - n), min(k, m)
    while lo <= hi:
        i = (lo + hi) // 2
        j = k - i
        aL = a[i - 1] if i > 0 else float("-inf")
        aR = a[i] if i < m else float("inf")
        bL = b[j - 1] if j > 0 else float("-inf")
        bR = b[j] if j < n else float("inf")
        if aL <= bR and bL <= aR:
            return max(aL, bL)
        if aL > bR:
            hi = i - 1
        else:
            lo = i + 1

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
    assert kth_two_sorted([1, 3, 5], [2, 4, 6], 4) == 4
    assert kth_two_sorted([1, 2], [3, 4], 1) == 1
    assert kth_two_sorted([2], [1, 3], 2) == 2
    assert kth_two_sorted([1, 3], [2], 3) == 3
    assert kth_two_sorted([], [5], 1) == 5
    assert stdlib_only()
    print("bs_33 OK")


if __name__ == "__main__":
    main()
