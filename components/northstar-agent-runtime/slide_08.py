"""slide_08: Minimum size subarray with sum at least target.

Variable window over non-negative numbers: expand right, and shrink left while the window sum still reaches the target.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_08_VERSION = "slide-08.v1"


def min_subarray_len(target, nums):
    """Smallest length of a contiguous subarray with sum >= target."""
    if target <= 0:
        return 0
    left = 0
    total = 0
    best = len(nums) + 1
    for right, v in enumerate(nums):
        total += v
        while total >= target:
            if right - left + 1 < best:
                best = right - left + 1
            total -= nums[left]
            left += 1
    return 0 if best == len(nums) + 1 else best

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
    assert min_subarray_len(7, [2, 3, 1, 2, 4, 3]) == 2
    assert min_subarray_len(4, [1, 4, 4]) == 1
    assert min_subarray_len(11, [1, 1, 1, 1, 1, 1, 1, 1]) == 0
    assert min_subarray_len(1, [1]) == 1
    assert min_subarray_len(15, [1, 2, 3, 4, 5]) == 5
    assert stdlib_only()
    print("slide_08 OK")


if __name__ == "__main__":
    main()
