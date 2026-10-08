"""slide_13: Count subarrays with sum at most k.

Variable window over non-negative numbers: for each right edge, every start in [left, right] yields a valid subarray.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_13_VERSION = "slide-13.v1"


def count_subarrays_sum_le_k(nums, k):
    """Count contiguous subarrays with sum <= k (nonneg nums)."""
    if k < 0:
        return 0
    left = 0
    total = 0
    count = 0
    for right, v in enumerate(nums):
        total += v
        while total > k:
            total -= nums[left]
            left += 1
        count += right - left + 1
    return count

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
    assert count_subarrays_sum_le_k([1, 2, 3], 3) == 4
    assert count_subarrays_sum_le_k([1, 1, 1], 2) == 5
    assert count_subarrays_sum_le_k([], 5) == 0
    assert count_subarrays_sum_le_k([5], 4) == 0
    assert count_subarrays_sum_le_k([2, 2, 2], 6) == 6
    assert stdlib_only()
    print("slide_13 OK")


if __name__ == "__main__":
    main()
