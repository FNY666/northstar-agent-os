"""slide_49: Find the power of k-size subarrays.

Fixed-size window tracking 'breaks' (adjacent pairs not ascending by 1): the power is the window max when there are none, else -1.

Time complexity: O(n) time
Space complexity: O(n) output
"""

import ast
import sys
SLIDE_49_VERSION = "slide-49.v1"


def results_k_power(nums, k):
    """Power of k-size subarrays: max if consecutive ascending, else -1."""
    n = len(nums)
    if k > n or k <= 0:
        return []
    out = []
    bad = 0
    for i in range(n):
        if i > 0 and nums[i] != nums[i - 1] + 1:
            bad += 1
        if i >= k:
            if nums[i - k + 1] != nums[i - k] + 1:
                bad -= 1
        if i >= k - 1:
            out.append(-1 if bad else nums[i])
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
    assert results_k_power([1, 2, 3, 4, 3, 2, 5], 3) == [3, 4, -1, -1, -1]
    assert results_k_power([2, 2, 2, 2, 2], 4) == [-1, -1]
    assert results_k_power([3, 2, 3, 2, 3, 2], 2) == [-1, 3, -1, 3, -1]
    assert results_k_power([1, 2, 3], 1) == [1, 2, 3]
    assert results_k_power([1, 2], 5) == []
    assert stdlib_only()
    print("slide_49 OK")


if __name__ == "__main__":
    main()
