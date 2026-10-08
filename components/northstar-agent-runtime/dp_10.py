"""dp-10: Longest increasing subsequence (length).

Length of the longest strictly increasing subsequence. Classic O(n^2) DP over pairs.

Time complexity: O(n^2) time
Space complexity: O(n) space
"""

import ast
import sys
from typing import List

DP_10_VERSION = "dp-10.v1"


def lis(nums: List[int]) -> int:
    """Return the length of the longest strictly increasing subsequence."""
    if not nums:
        return 0
    dp = [1] * len(nums)
    for i in range(len(nums)):
        for j in range(i):
            if nums[j] < nums[i]:
                dp[i] = max(dp[i], dp[j] + 1)
    return max(dp)


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
    assert lis([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis([0, 1, 0, 3, 2, 3]) == 4
    assert lis([]) == 0
    assert lis([7, 7, 7]) == 1
    assert lis([1, 2, 3, 4]) == 4
    assert lis([4, 3, 2, 1]) == 1
    assert stdlib_only()
    print("dp-10 OK")


if __name__ == "__main__":
    main()
