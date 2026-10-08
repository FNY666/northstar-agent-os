"""slide_27: Subarrays with k different integers.

Subarrays with exactly k distinct integers via at-most windows: count(<= k) - count(<= k - 1).

Time complexity: O(n) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
SLIDE_27_VERSION = "slide-27.v1"


def subarrays_k_distinct(nums, k):
    """Count subarrays with exactly k distinct integers."""
    def at_most(k):
        if k <= 0:
            return 0
        counts = {}
        left = 0
        total = 0
        for right, v in enumerate(nums):
            counts[v] = counts.get(v, 0) + 1
            while len(counts) > k:
                counts[nums[left]] -= 1
                if counts[nums[left]] == 0:
                    del counts[nums[left]]
                left += 1
            total += right - left + 1
        return total
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
    assert subarrays_k_distinct([1, 2, 1, 2, 3], 2) == 7
    assert subarrays_k_distinct([1, 2, 1, 3, 4], 3) == 3
    assert subarrays_k_distinct([1], 1) == 1
    assert subarrays_k_distinct([1, 1, 1], 1) == 6
    assert subarrays_k_distinct([1, 2], 3) == 0
    assert stdlib_only()
    print("slide_27 OK")


if __name__ == "__main__":
    main()
