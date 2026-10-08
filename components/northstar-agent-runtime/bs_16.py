"""bs_16: Kth smallest in sorted matrix

Kth smallest element of an n x n matrix with rows and columns
sorted, via binary search on the value range.

Time complexity: O(n log(max-min)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_16_VERSION = "bs-16.v1"


def kth_smallest_matrix(m, k):
    """Return the kth smallest element (1-indexed) of a sorted matrix."""
    n = len(m)
    lo, hi = m[0][0], m[-1][-1]

    def count_le(x):
        cnt, r, c = 0, n - 1, 0
        while r >= 0 and c < n:
            if m[r][c] <= x:
                cnt += r + 1
                c += 1
            else:
                r -= 1
        return cnt

    while lo < hi:
        mid = (lo + hi) // 2
        if count_le(mid) < k:
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
    assert kth_smallest_matrix([[1, 5, 9], [10, 11, 13], [12, 13, 15]], 8) == 13
    assert kth_smallest_matrix([[1, 5, 9], [10, 11, 13], [12, 13, 15]], 1) == 1
    assert kth_smallest_matrix([[1, 2], [1, 3]], 2) == 1
    assert kth_smallest_matrix([[-5]], 1) == -5
    assert kth_smallest_matrix([[1, 5, 9], [10, 11, 13], [12, 13, 15]], 9) == 15
    assert stdlib_only()
    print("bs_16 OK")


if __name__ == "__main__":
    main()
