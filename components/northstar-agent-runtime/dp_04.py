"""dp-04: House robber II (circular street).

Houses form a circle, so the first and last cannot both be robbed. Answer is max of robbing nums[:-1] and robbing nums[1:].

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_04_VERSION = "dp-04.v1"


def rob_circular(nums: List[int]) -> int:
    """Return max loot on a circular street (first/last are adjacent)."""
    def linear(a: List[int]) -> int:
        p2 = p1 = 0
        for x in a:
            p2, p1 = p1, max(p1, p2 + x)
        return p1
    if not nums:
        return 0
    if len(nums) == 1:
        return nums[0]
    return max(linear(nums[:-1]), linear(nums[1:]))


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
    assert rob_circular([2, 3, 2]) == 3
    assert rob_circular([1, 2, 3, 1]) == 4
    assert rob_circular([1, 2, 3]) == 3
    assert rob_circular([5]) == 5
    assert rob_circular([]) == 0
    assert stdlib_only()
    print("dp-04 OK")


if __name__ == "__main__":
    main()
