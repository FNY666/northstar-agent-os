"""bs_32: Median of two sorted arrays

Median of two sorted arrays via binary search on the partition
point of the shorter array.

Time complexity: O(log(min(m, n))) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_32_VERSION = "bs-32.v1"


def median_two_sorted(a, b):
    """Return the median of two sorted arrays."""
    if len(a) > len(b):
        a, b = b, a
    m, n = len(a), len(b)
    lo, hi = 0, m
    while lo <= hi:
        i = (lo + hi) // 2
        j = (m + n + 1) // 2 - i
        aL = a[i - 1] if i > 0 else float("-inf")
        aR = a[i] if i < m else float("inf")
        bL = b[j - 1] if j > 0 else float("-inf")
        bR = b[j] if j < n else float("inf")
        if aL <= bR and bL <= aR:
            if (m + n) % 2:
                return max(aL, bL)
            return (max(aL, bL) + min(aR, bR)) / 2
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
    assert median_two_sorted([1, 3], [2]) == 2
    assert median_two_sorted([1, 2], [3, 4]) == 2.5
    assert median_two_sorted([0, 0], [0, 0]) == 0.0
    assert median_two_sorted([], [1]) == 1
    assert median_two_sorted([1, 2, 3], [4, 5, 6, 7]) == 4
    assert stdlib_only()
    print("bs_32 OK")


if __name__ == "__main__":
    main()
