"""slide_37: Minimum operations to reduce x to zero.

Removing from the ends to reach x equals keeping the longest middle subarray summing to total - x.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_37_VERSION = "slide-37.v1"


def min_ops_reduce_x(nums, x):
    """Min ops removing from ends so the removed sum equals x."""
    total = sum(nums)
    target = total - x
    if target < 0:
        return -1
    if target == 0:
        return len(nums)
    left = 0
    cur = 0
    best = -1
    for right, v in enumerate(nums):
        cur += v
        while cur > target:
            cur -= nums[left]
            left += 1
        if cur == target and right - left + 1 > best:
            best = right - left + 1
    return -1 if best == -1 else len(nums) - best

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
    assert min_ops_reduce_x([1, 1, 4, 2, 3], 5) == 2
    assert min_ops_reduce_x([5, 6, 7, 8, 9], 4) == -1
    assert min_ops_reduce_x([3, 2, 20, 1, 1, 3], 10) == 5
    assert min_ops_reduce_x([1, 1], 3) == -1
    assert min_ops_reduce_x([1, 1, 1], 2) == 2
    assert stdlib_only()
    print("slide_37 OK")


if __name__ == "__main__":
    main()
