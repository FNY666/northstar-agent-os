"""bs_42: Magnetic force between balls

Place m balls in positions to maximize the minimum magnetic
force between any two (binary search on answer).

Time complexity: O(n log(range)) time
Space complexity: O(n) for the sort"""

import ast
import sys
BS_42_VERSION = "bs-42.v1"


def max_distance_balls(position, m):
    """Return the maximized minimum distance for m balls."""
    position = sorted(position)

    def can(d):
        cnt, last = 1, position[0]
        for p in position[1:]:
            if p - last >= d:
                cnt += 1
                last = p
        return cnt >= m

    lo, hi = 1, position[-1] - position[0]
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
    assert max_distance_balls([1, 2, 3, 4, 7], 3) == 3
    assert max_distance_balls([5, 4, 3, 2, 1, 1000000000], 2) == 999999999
    assert max_distance_balls([1, 2, 3], 2) == 2
    assert max_distance_balls([1, 2], 2) == 1
    assert stdlib_only()
    print("bs_42 OK")


if __name__ == "__main__":
    main()
