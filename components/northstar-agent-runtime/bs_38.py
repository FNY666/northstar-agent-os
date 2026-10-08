"""bs_38: Aggressive cows

Place k cows in stalls to maximize the minimum distance
between any two (binary search on answer).

Time complexity: O(n log(range)) time
Space complexity: O(n) for the sort"""

import ast
import sys
BS_38_VERSION = "bs-38.v1"


def aggressive_cows(stalls, k):
    """Return the largest achievable minimum distance for k cows."""
    stalls = sorted(stalls)

    def can(d):
        cnt, last = 1, stalls[0]
        for s in stalls[1:]:
            if s - last >= d:
                cnt += 1
                last = s
        return cnt >= k

    lo, hi = 1, stalls[-1] - stalls[0]
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if can(mid):
            lo = mid
        else:
            hi = mid - 1
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
    assert aggressive_cows([1, 2, 8, 4, 9], 3) == 3
    assert aggressive_cows([1, 2, 3], 2) == 2
    assert aggressive_cows([1, 2, 4, 8, 9], 3) == 3
    assert aggressive_cows([1, 100], 2) == 99
    assert stdlib_only()
    print("bs_38 OK")


if __name__ == "__main__":
    main()
