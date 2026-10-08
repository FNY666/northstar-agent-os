"""bs_41: Minimum days for bouquets

Minimum day to make m bouquets of k adjacent bloomed flowers
(binary search on answer).

Time complexity: O(n log(range)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_41_VERSION = "bs-41.v1"


def min_days_bouquets(bloom, m, k):
    """Return the minimum day for m bouquets of k adjacent flowers."""
    if m * k > len(bloom):
        return -1

    def bouquets(day):
        cnt, run = 0, 0
        for b in bloom:
            if b <= day:
                run += 1
            else:
                run = 0
            if run == k:
                cnt += 1
                run = 0
        return cnt

    lo, hi = min(bloom), max(bloom)
    while lo < hi:
        mid = (lo + hi) // 2
        if bouquets(mid) >= m:
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
    assert min_days_bouquets([1, 10, 3, 10, 2], 3, 1) == 3
    assert min_days_bouquets([5, 5, 5, 5], 2, 2) == 5
    assert min_days_bouquets([1, 2, 3], 2, 2) == -1
    assert min_days_bouquets([1, 2, 4, 9, 3], 2, 2) == 4
    assert stdlib_only()
    print("bs_41 OK")


if __name__ == "__main__":
    main()
