"""slide_43: Minimum operations to make array continuous.

Sort unique values, then find the longest window fitting in a range of size n: the rest must be replaced.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
SLIDE_43_VERSION = "slide-43.v1"


def min_ops_continuous(nums):
    """Min operations to make the array continuous."""
    n = len(nums)
    uniq = sorted(set(nums))
    left = 0
    best = 0
    for right, v in enumerate(uniq):
        while v - uniq[left] >= n:
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
    return n - best

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
    assert min_ops_continuous([4, 2, 3, 1, 5]) == 0
    assert min_ops_continuous([1, 2, 3, 5, 6]) == 1
    assert min_ops_continuous([1, 10, 100, 1000]) == 3
    assert min_ops_continuous([8, 5, 9, 9, 8, 4]) == 2
    assert min_ops_continuous([1]) == 0
    assert stdlib_only()
    print("slide_43 OK")


if __name__ == "__main__":
    main()
