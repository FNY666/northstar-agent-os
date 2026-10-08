"""bs_40: Painter's partition

Minimum time for k painters to paint contiguous boards
(binary search on answer).

Time complexity: O(n log(sum)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_40_VERSION = "bs-40.v1"


def painters_partition(boards, k):
    """Return the minimum time for k painters over contiguous boards."""
    lo, hi = max(boards), sum(boards)

    def painters(limit):
        cnt, cur = 1, 0
        for b in boards:
            if cur + b > limit:
                cnt += 1
                cur = b
            else:
                cur += b
        return cnt

    while lo < hi:
        mid = (lo + hi) // 2
        if painters(mid) <= k:
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
    assert painters_partition([10, 20, 30, 40], 2) == 60
    assert painters_partition([5, 5, 5, 5], 2) == 10
    assert painters_partition([1, 2, 3], 3) == 3
    assert painters_partition([7], 1) == 7
    assert stdlib_only()
    print("bs_40 OK")


if __name__ == "__main__":
    main()
