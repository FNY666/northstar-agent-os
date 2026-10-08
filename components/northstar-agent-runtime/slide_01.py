"""slide_01: Maximum sum subarray of size k.

Fixed-size sliding window: keep a running sum of the current window of length k and track the largest value seen.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_01_VERSION = "slide-01.v1"


def max_sum_k(nums, k):
    """Return the maximum sum of any contiguous subarray of length k."""
    if not nums or k <= 0:
        return 0
    n = len(nums)
    if k >= n:
        return sum(nums)
    window = sum(nums[:k])
    best = window
    for i in range(k, n):
        window += nums[i] - nums[i - k]
        if window > best:
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
    assert max_sum_k([1, 4, 2, 10, 23, 3, 1, 0, 20], 4) == 39
    assert max_sum_k([2, 3], 1) == 3
    assert max_sum_k([5], 1) == 5
    assert max_sum_k([1, 2, 3, 4, 5], 5) == 15
    assert max_sum_k([], 3) == 0
    assert max_sum_k([-1, -2, -3], 2) == -3
    assert stdlib_only()
    print("slide_01 OK")


if __name__ == "__main__":
    main()
