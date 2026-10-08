"""greedy_44: Minimize maximum pair sum.

Pair the smallest with the largest; this greedy pairing minimizes the largest pair sum.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_44_VERSION = "greedy-44.v1"


def min_max_pair_sum(nums):
    """Return the minimized maximum pair sum after optimal pairing."""
    nums = sorted(nums)
    n = len(nums)
    return max(nums[i] + nums[n - 1 - i] for i in range(n // 2))

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
    assert min_max_pair_sum([3, 5, 2, 3]) == 7
    assert min_max_pair_sum([3, 5, 4, 2, 4, 6]) == 8
    assert min_max_pair_sum([1, 2]) == 3
    assert min_max_pair_sum([1, 100, 2, 99]) == 101
    assert stdlib_only()
    print("greedy_44 OK")


if __name__ == "__main__":
    main()
