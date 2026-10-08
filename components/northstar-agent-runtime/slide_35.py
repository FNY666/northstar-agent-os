"""slide_35: Maximum sum of distinct subarrays of length k.

Fixed-size window with a frequency map: only windows whose distinct count equals k are candidates for the best sum.

Time complexity: O(n) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
SLIDE_35_VERSION = "slide-35.v1"


def max_sum_distinct_k(nums, k):
    """Max sum of a length-k subarray with all distinct elements."""
    n = len(nums)
    if n == 0 or k <= 0 or k > n:
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
        if i >= k - 1 and len(counts) == k and window > best:
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
    assert max_sum_distinct_k([1, 5, 4, 2, 9, 9, 9], 3) == 15
    assert max_sum_distinct_k([4, 4, 4], 3) == 0
    assert max_sum_distinct_k([1, 2, 3], 3) == 6
    assert max_sum_distinct_k([1, 1, 2], 2) == 3
    assert max_sum_distinct_k([], 2) == 0
    assert stdlib_only()
    print("slide_35 OK")


if __name__ == "__main__":
    main()
