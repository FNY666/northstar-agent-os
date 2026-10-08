"""bs_43: Minimize max difference of pairs

Minimize the maximum difference among p pairs from nums
(binary search on answer).

Time complexity: O(n log(range)) time
Space complexity: O(n) for the sort"""

import ast
import sys
BS_43_VERSION = "bs-43.v1"


def minimize_max_diff(nums, p):
    """Return the minimized maximum pair difference for p pairs."""
    nums = sorted(nums)

    def pairs(diff):
        cnt, i = 0, 1
        while i < len(nums):
            if nums[i] - nums[i - 1] <= diff:
                cnt += 1
                i += 2
            else:
                i += 1
        return cnt

    lo, hi = 0, nums[-1] - nums[0]
    while lo < hi:
        mid = (lo + hi) // 2
        if pairs(mid) >= p:
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
    assert minimize_max_diff([10, 1, 2, 7, 1, 3], 2) == 1
    assert minimize_max_diff([4, 2, 1, 2], 1) == 0
    assert minimize_max_diff([1, 2, 3, 4], 2) == 1
    assert minimize_max_diff([1, 100], 1) == 99
    assert stdlib_only()
    print("bs_43 OK")


if __name__ == "__main__":
    main()
