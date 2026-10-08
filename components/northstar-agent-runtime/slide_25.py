"""slide_25: Longest subarray with absolute difference limit.

Variable window with two monotonic deques tracking the window max and min: shrink left while max - min exceeds the limit.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
SLIDE_25_VERSION = "slide-25.v1"


def longest_subarray_limit(nums, limit):
    """Longest subarray with max - min <= limit."""
    max_dq = []
    min_dq = []
    max_h = 0
    min_h = 0
    left = 0
    best = 0
    for right, v in enumerate(nums):
        while len(max_dq) > max_h and nums[max_dq[-1]] <= v:
            max_dq.pop()
        max_dq.append(right)
        while len(min_dq) > min_h and nums[min_dq[-1]] >= v:
            min_dq.pop()
        min_dq.append(right)
        while nums[max_dq[max_h]] - nums[min_dq[min_h]] > limit:
            left += 1
            if max_dq[max_h] < left:
                max_h += 1
            if min_dq[min_h] < left:
                min_h += 1
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
    assert longest_subarray_limit([8, 2, 4, 7], 4) == 2
    assert longest_subarray_limit([10, 1, 2, 4, 7, 2], 5) == 4
    assert longest_subarray_limit([4, 2, 2, 2, 4, 4, 2, 2], 0) == 3
    assert longest_subarray_limit([1], 0) == 1
    assert longest_subarray_limit([1, 5], 4) == 2
    assert stdlib_only()
    print("slide_25 OK")


if __name__ == "__main__":
    main()
