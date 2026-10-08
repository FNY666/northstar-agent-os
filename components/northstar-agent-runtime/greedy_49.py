"""greedy_49: Largest perimeter triangle.

Sort descending; the first triple satisfying the triangle inequality is optimal.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_49_VERSION = "greedy-49.v1"


def largest_perimeter(nums):
    """Return the largest perimeter of a non-degenerate triangle, or 0."""
    nums = sorted(nums, reverse=True)
    for i in range(len(nums) - 2):
        if nums[i] < nums[i + 1] + nums[i + 2]:
            return nums[i] + nums[i + 1] + nums[i + 2]
    return 0

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
    assert largest_perimeter([2, 1, 2]) == 5
    assert largest_perimeter([1, 2, 1]) == 0
    assert largest_perimeter([3, 6, 2, 3]) == 8
    assert largest_perimeter([]) == 0
    assert stdlib_only()
    print("greedy_49 OK")


if __name__ == "__main__":
    main()
