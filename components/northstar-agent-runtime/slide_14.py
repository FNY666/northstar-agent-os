"""slide_14: Count subarrays with at most k odd numbers.

Variable window counting odd entries: shrink the left edge whenever the window holds more than k odds.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_14_VERSION = "slide-14.v1"


def count_at_most_k_odd(nums, k):
    """Count contiguous subarrays with at most k odd numbers."""
    if k < 0:
        return 0
    left = 0
    odds = 0
    count = 0
    for right, v in enumerate(nums):
        if v % 2 == 1:
            odds += 1
        while odds > k:
            if nums[left] % 2 == 1:
                odds -= 1
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
    assert count_at_most_k_odd([1, 2, 3, 4], 1) == 8
    assert count_at_most_k_odd([2, 4, 6], 0) == 6
    assert count_at_most_k_odd([1, 3, 5], 2) == 5
    assert count_at_most_k_odd([1], 0) == 0
    assert count_at_most_k_odd([], 1) == 0
    assert stdlib_only()
    print("slide_14 OK")


if __name__ == "__main__":
    main()
