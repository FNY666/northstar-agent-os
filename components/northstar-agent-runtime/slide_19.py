"""slide_19: Longest subarray with sum at most k.

Variable window over non-negative numbers: expand right and shrink left whenever the window sum exceeds k.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_19_VERSION = "slide-19.v1"


def longest_subarray_sum_le_k(nums, k):
    """Longest contiguous subarray with sum <= k (nonneg nums)."""
    left = 0
    total = 0
    best = 0
    for right, v in enumerate(nums):
        total += v
        while total > k:
            total -= nums[left]
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
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
    assert longest_subarray_sum_le_k([1, 2, 3], 3) == 2
    assert longest_subarray_sum_le_k([3, 1, 2, 1], 4) == 3
    assert longest_subarray_sum_le_k([], 5) == 0
    assert longest_subarray_sum_le_k([5], 4) == 0
    assert longest_subarray_sum_le_k([1, 1, 1], 3) == 3
    assert stdlib_only()
    print("slide_19 OK")


if __name__ == "__main__":
    main()
