"""slide_26: Count number of nice subarrays.

Subarrays with exactly k odd numbers via at-most windows: count(<= k) - count(<= k - 1).

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_26_VERSION = "slide-26.v1"


def number_of_nice(nums, k):
    """Count subarrays with exactly k odd numbers."""
    def at_most(k):
        if k < 0:
            return 0
        left = 0
        odds = 0
        count = 0
        for right, v in enumerate(nums):
            odds += v % 2
            while odds > k:
                odds -= nums[left] % 2
                left += 1
            count += right - left + 1
        return count
    return at_most(k) - at_most(k - 1)

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
    assert number_of_nice([1, 1, 2, 1, 1], 3) == 2
    assert number_of_nice([2, 4, 6], 1) == 0
    assert number_of_nice([2, 2, 2, 1, 2, 2, 1, 2, 2, 2], 2) == 16
    assert number_of_nice([1], 1) == 1
    assert number_of_nice([], 1) == 0
    assert stdlib_only()
    print("slide_26 OK")


if __name__ == "__main__":
    main()
