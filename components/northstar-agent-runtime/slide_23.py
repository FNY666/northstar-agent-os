"""slide_23: Binary subarrays with sum.

Count subarrays summing to goal via at-most prefix windows: count(sum <= goal) - count(sum <= goal - 1).

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_23_VERSION = "slide-23.v1"


def num_subarrays_sum_goal(nums, goal):
    """Count subarrays of a binary array summing to goal."""
    def at_most(k):
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
    return at_most(goal) - at_most(goal - 1)

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
    assert num_subarrays_sum_goal([1, 0, 1, 0, 1], 2) == 4
    assert num_subarrays_sum_goal([0, 0, 0, 0, 0], 0) == 15
    assert num_subarrays_sum_goal([1, 1, 1], 2) == 2
    assert num_subarrays_sum_goal([1, 0], 1) == 2
    assert num_subarrays_sum_goal([0], 1) == 0
    assert stdlib_only()
    print("slide_23 OK")


if __name__ == "__main__":
    main()
