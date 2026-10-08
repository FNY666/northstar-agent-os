"""bs_44: Minimum bag limit

Minimum penalty after at most maxOperations splits of balls
into bags (binary search on answer).

Time complexity: O(n log(max)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_44_VERSION = "bs-44.v1"


def minimum_bag_limit(nums, maxOperations):
    """Return the minimum possible maximum balls per bag."""
    lo, hi = 1, max(nums)

    def needed(limit):
        return sum((x - 1) // limit for x in nums)

    while lo < hi:
        mid = (lo + hi) // 2
        if needed(mid) <= maxOperations:
            hi = mid
        else:
            lo = mid + 1
    return lo

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
    assert minimum_bag_limit([9], 2) == 3
    assert minimum_bag_limit([2, 4, 8, 2], 4) == 2
    assert minimum_bag_limit([7, 17], 2) == 7
    assert minimum_bag_limit([5], 0) == 5
    assert stdlib_only()
    print("bs_44 OK")


if __name__ == "__main__":
    main()
