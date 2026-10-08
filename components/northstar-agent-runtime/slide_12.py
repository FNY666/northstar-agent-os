"""slide_12: Count subarrays with product less than k.

Variable window over positive numbers: every window ending at right contributes (right - left + 1) valid subarrays.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_12_VERSION = "slide-12.v1"


def num_subarray_product_less_k(nums, k):
    """Count contiguous subarrays with product < k (positive nums)."""
    if k <= 1:
        return 0
    prod = 1
    left = 0
    count = 0
    for right, v in enumerate(nums):
        prod *= v
        while prod >= k:
            prod //= nums[left]
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
    assert num_subarray_product_less_k([10, 5, 2, 6], 100) == 8
    assert num_subarray_product_less_k([1, 2, 3], 0) == 0
    assert num_subarray_product_less_k([1, 1, 1], 2) == 6
    assert num_subarray_product_less_k([10], 100) == 1
    assert num_subarray_product_less_k([], 5) == 0
    assert stdlib_only()
    print("slide_12 OK")


if __name__ == "__main__":
    main()
