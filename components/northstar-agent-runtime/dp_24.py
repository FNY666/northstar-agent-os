"""dp-24: Maximum subarray (Kadane).

Largest sum of any contiguous subarray. Track the best sum ending at each position and the best seen overall.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_24_VERSION = "dp-24.v1"


def max_subarray(nums: List[int]) -> int:
    """Return the maximum sum of any contiguous subarray."""
    if not nums:
        raise ValueError("nums must be non-empty")
    best = cur = nums[0]
    for x in nums[1:]:
        cur = max(x, cur + x)
        best = max(best, cur)
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
    assert max_subarray([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 6
    assert max_subarray([1]) == 1
    assert max_subarray([-1]) == -1
    assert max_subarray([5, 4, -1, 7, 8]) == 23
    assert max_subarray([-2, -1]) == -1
    try:
        max_subarray([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-24 OK")


if __name__ == "__main__":
    main()
