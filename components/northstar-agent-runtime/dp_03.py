"""dp-03: House robber.

Max loot without robbing adjacent houses. dp[i] = max(dp[i-1], dp[i-2]+nums[i]); only two rolling values are kept.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_03_VERSION = "dp-03.v1"


def rob(nums: List[int]) -> int:
    """Return the maximum loot without robbing two adjacent houses."""
    prev2 = prev1 = 0
    for x in nums:
        prev2, prev1 = prev1, max(prev1, prev2 + x)
    return prev1


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
    assert rob([1, 2, 3, 1]) == 4
    assert rob([2, 7, 9, 3, 1]) == 12
    assert rob([]) == 0
    assert rob([5]) == 5
    assert rob([2, 1, 1, 2]) == 4
    assert stdlib_only()
    print("dp-03 OK")


if __name__ == "__main__":
    main()
