"""lis-35: Minimum decreasing-subsequence partition.

Greedy patience piles; count equals the LIS length (Dilworth dual).

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_35_VERSION = "lis-35.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def min_decreasing_partition(seq):
    """Fewest strictly decreasing subsequences partitioning seq."""
    a = _check_seq(seq)
    tops = []
    for x in a:
        i = bisect.bisect_right(tops, x)
        if i == len(tops):
            bisect.insort(tops, x)
        else:
            tops[i] = x
    return len(tops)

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
    assert min_decreasing_partition([1, 2, 3]) == 3
    assert min_decreasing_partition([3, 2, 1]) == 1
    assert min_decreasing_partition([]) == 0
    assert stdlib_only()
    print("lis-35 OK")


if __name__ == "__main__":
    main()
