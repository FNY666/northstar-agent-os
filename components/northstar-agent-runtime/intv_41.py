"""intv_41: Jump game II minimum jumps (min_jumps).

Greedy layers: each jump extends to the farthest reachable point.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_41 = "intv-41.v1"


def min_jumps(nums):
    """Minimum jumps to reach the last index."""
    n = len(nums)
    if n <= 1:
        return 0
    jumps = 0
    cur_end = cur_far = 0
    for i in range(n - 1):
        if i + nums[i] > cur_far:
            cur_far = i + nums[i]
        if i == cur_end:
            jumps += 1
            cur_end = cur_far
    return jumps

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
    assert min_jumps([2, 3, 1, 1, 4]) == 2
    assert min_jumps([2, 3, 0, 1, 4]) == 2
    assert min_jumps([0]) == 0
    assert min_jumps([1, 1, 1, 1]) == 3
    assert min_jumps([5, 1, 1, 1, 1]) == 1
    assert stdlib_only()
    print("intv_41 OK")


if __name__ == "__main__":
    main()
