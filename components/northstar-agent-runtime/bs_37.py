"""bs_37: Smallest divisor

Smallest divisor d such that the sum of ceil divisions of nums
by d stays within threshold (binary search on answer).

Time complexity: O(n log(max)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_37_VERSION = "bs-37.v1"


def smallest_divisor(nums, threshold):
    """Return the smallest divisor with division-sum <= threshold."""
    lo, hi = 1, max(nums)

    def total(d):
        return sum((x + d - 1) // d for x in nums)

    while lo < hi:
        mid = (lo + hi) // 2
        if total(mid) <= threshold:
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
    assert smallest_divisor([1, 2, 5, 9], 6) == 5
    assert smallest_divisor([44, 22, 33, 11, 1], 5) == 44
    assert smallest_divisor([2, 3, 5, 7, 11], 11) == 3
    assert smallest_divisor([1], 1) == 1
    assert stdlib_only()
    print("bs_37 OK")


if __name__ == "__main__":
    main()
