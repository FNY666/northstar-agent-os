"""slide_42: Frequency of the most frequent element.

Sort, then use a variable window: the window can be raised to its max when the required increments fit in k.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_42_VERSION = "slide-42.v1"


def max_frequency(nums, k):
    """Max frequency of any element after at most k increments."""
    nums = sorted(nums)
    left = 0
    total = 0
    best = 0
    for right, v in enumerate(nums):
        total += v
        while v * (right - left + 1) - total > k:
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
    assert max_frequency([1, 2, 4], 5) == 3
    assert max_frequency([1, 4, 8, 13], 5) == 2
    assert max_frequency([3, 9, 6], 2) == 1
    assert max_frequency([1], 100) == 1
    assert max_frequency([1, 1, 1], 0) == 3
    assert stdlib_only()
    print("slide_42 OK")


if __name__ == "__main__":
    main()
