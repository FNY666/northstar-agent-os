"""slide_50: Longest nice subarray.

Variable window on bitmasks: a window is nice while no bit is set in two different numbers; shrink on the first conflict.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_50_VERSION = "slide-50.v1"


def longest_nice_and(nums):
    """Longest subarray where every pair has bitwise AND equal to 0."""
    used = 0
    left = 0
    best = 0
    for right, v in enumerate(nums):
        while used & v:
            used ^= nums[left]
            left += 1
        used |= v
        if right - left + 1 > best:
            best = right - left + 1
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
    assert longest_nice_and([1, 3, 8, 48, 10]) == 3
    assert longest_nice_and([3, 1, 5, 11, 13]) == 1
    assert longest_nice_and([1]) == 1
    assert longest_nice_and([8, 8]) == 1
    assert longest_nice_and([16, 8, 4, 2, 1]) == 5
    assert longest_nice_and([]) == 0
    assert stdlib_only()
    print("slide_50 OK")


if __name__ == "__main__":
    main()
