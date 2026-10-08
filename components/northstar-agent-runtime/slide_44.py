"""slide_44: Maximum erasure value.

Variable window with unique elements: track the running sum and shrink past the previous duplicate when one appears.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
SLIDE_44_VERSION = "slide-44.v1"


def max_erasure(nums):
    """Maximum sum of a subarray with all unique elements."""
    seen = {}
    left = 0
    total = 0
    best = 0
    for right, v in enumerate(nums):
        if v in seen and seen[v] >= left:
            while left <= seen[v]:
                total -= nums[left]
                left += 1
        seen[v] = right
        total += v
        if total > best:
            best = total
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
    assert max_erasure([4, 2, 4, 5, 6]) == 17
    assert max_erasure([5, 2, 1, 2, 5, 2, 1, 2, 5]) == 8
    assert max_erasure([1]) == 1
    assert max_erasure([1, 2, 3]) == 6
    assert max_erasure([]) == 0
    assert stdlib_only()
    print("slide_44 OK")


if __name__ == "__main__":
    main()
