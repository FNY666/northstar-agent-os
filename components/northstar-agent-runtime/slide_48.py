"""slide_48: Maximum sum of almost unique subarray.

Fixed-size window with a frequency map: only windows with at least m distinct elements are candidates for the best sum.

Time complexity: O(n) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
SLIDE_48_VERSION = "slide-48.v1"


def max_sum_almost_unique(nums, m, k):
    """Max sum of a length-k subarray with at least m distinct elements."""
    n = len(nums)
    if n == 0 or k <= 0 or k > n or m <= 0:
        return 0
    counts = {}
    window = 0
    best = 0
    for i, v in enumerate(nums):
        counts[v] = counts.get(v, 0) + 1
        window += v
        if i >= k:
            lv = nums[i - k]
            counts[lv] -= 1
            if counts[lv] == 0:
                del counts[lv]
            window -= lv
        if i >= k - 1 and len(counts) >= m and window > best:
            best = window
    return best

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
    assert max_sum_almost_unique([2, 6, 7, 3, 1, 7], 3, 3) == 16
    assert max_sum_almost_unique([5, 9, 9, 2, 4, 5, 4], 1, 3) == 23
    assert max_sum_almost_unique([1, 2, 1, 2], 1, 2) == 3
    assert max_sum_almost_unique([1, 1, 1, 7, 8, 8], 2, 4) == 24
    assert max_sum_almost_unique([], 1, 2) == 0
    assert stdlib_only()
    print("slide_48 OK")


if __name__ == "__main__":
    main()
