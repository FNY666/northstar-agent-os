"""greedy_18: Wiggle subsequence.

Count direction flips; greedy two-counter scan equals the longest alternating subsequence length.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_18_VERSION = "greedy-18.v1"


def wiggle_max_length(nums):
    """Return the length of the longest wiggle subsequence."""
    if len(nums) < 2:
        return len(nums)
    up = 1
    down = 1
    for i in range(1, len(nums)):
        if nums[i] > nums[i - 1]:
            up = down + 1
        elif nums[i] < nums[i - 1]:
            down = up + 1
    return max(up, down)

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
    assert wiggle_max_length([1, 7, 4, 9, 2, 5]) == 6
    assert wiggle_max_length([1, 17, 5, 10, 13, 15, 10, 5, 16, 8]) == 7
    assert wiggle_max_length([]) == 0
    assert wiggle_max_length([1, 2, 3, 4, 5, 6, 7, 8, 9]) == 2
    assert stdlib_only()
    print("greedy_18 OK")


if __name__ == "__main__":
    main()
