"""slide_41: Count subarrays where max element appears at least k times.

Variable window on the global maximum: once the window holds k copies, every extension to the right is valid.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_41_VERSION = "slide-41.v1"


def count_max_freq_k(nums, k):
    """Count subarrays where the maximum element appears at least k times."""
    n = len(nums)
    if n == 0:
        return 0
    if k <= 0:
        return n * (n + 1) // 2
    mx = max(nums)
    left = 0
    freq = 0
    count = 0
    for right, v in enumerate(nums):
        if v == mx:
            freq += 1
        while freq >= k:
            count += n - right
            if nums[left] == mx:
                freq -= 1
            left += 1
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
    assert count_max_freq_k([1, 3, 2, 3, 3], 2) == 6
    assert count_max_freq_k([1, 1, 1], 1) == 6
    assert count_max_freq_k([2, 2], 2) == 1
    assert count_max_freq_k([1, 2, 3], 2) == 0
    assert count_max_freq_k([3, 3, 3], 3) == 1
    assert stdlib_only()
    print("slide_41 OK")


if __name__ == "__main__":
    main()
