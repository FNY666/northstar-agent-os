"""bs_39: Split array largest sum

Split nums into k subarrays minimizing the largest subarray
sum (binary search on answer).

Time complexity: O(n log(sum)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_39_VERSION = "bs-39.v1"


def split_array(nums, k):
    """Return the minimized largest sum over k subarrays."""
    lo, hi = max(nums), sum(nums)

    def pieces(limit):
        cnt, cur = 1, 0
        for x in nums:
            if cur + x > limit:
                cnt += 1
                cur = x
            else:
                cur += x
        return cnt

    while lo < hi:
        mid = (lo + hi) // 2
        if pieces(mid) <= k:
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
    assert split_array([7, 2, 5, 10, 8], 2) == 18
    assert split_array([1, 2, 3, 4, 5], 2) == 9
    assert split_array([1, 4, 4], 3) == 4
    assert split_array([10], 1) == 10
    assert stdlib_only()
    print("bs_39 OK")


if __name__ == "__main__":
    main()
