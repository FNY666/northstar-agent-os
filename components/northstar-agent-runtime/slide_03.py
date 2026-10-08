"""slide_03: Averages of all subarrays of size k.

Fixed-size sliding window: slide a running sum across the array and emit window / k for every position.

Time complexity: O(n) time
Space complexity: O(n) output
"""

import ast
import sys
SLIDE_03_VERSION = "slide-03.v1"


def averages_k(nums, k):
    """Return the average of every contiguous subarray of length k."""
    n = len(nums)
    if n == 0 or k <= 0 or k > n:
        return []
    window = sum(nums[:k])
    out = [window / k]
    for i in range(k, n):
        window += nums[i] - nums[i - k]
        out.append(window / k)
    return out

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
    assert averages_k([1, 3, 2, 6, -1, 4, 1, 8, 2], 5) == [2.2, 2.8, 2.4, 3.6, 2.8]
    assert averages_k([1, 2, 3], 1) == [1.0, 2.0, 3.0]
    assert averages_k([], 3) == []
    assert averages_k([5, 5], 2) == [5.0]
    assert averages_k([1, 2], 5) == []
    assert stdlib_only()
    print("slide_03 OK")


if __name__ == "__main__":
    main()
