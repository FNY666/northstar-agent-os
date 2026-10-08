"""slide_22: Longest ones after deleting one element.

Variable window allowing at most one zero: the answer is the window length minus the single deleted element.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_22_VERSION = "slide-22.v1"


def longest_ones_delete_one(nums):
    """Longest run of 1s after deleting exactly one element."""
    left = 0
    zeros = 0
    best = 0
    for right, v in enumerate(nums):
        if v == 0:
            zeros += 1
        while zeros > 1:
            if nums[left] == 0:
                zeros -= 1
            left += 1
        if right - left > best:
            best = right - left
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
    assert longest_ones_delete_one([1, 1, 0, 1]) == 3
    assert longest_ones_delete_one([0, 1, 1, 1, 0, 1, 1, 0, 1]) == 5
    assert longest_ones_delete_one([1, 1, 1]) == 2
    assert longest_ones_delete_one([0, 0, 0]) == 0
    assert longest_ones_delete_one([1, 0, 1]) == 2
    assert stdlib_only()
    print("slide_22 OK")


if __name__ == "__main__":
    main()
