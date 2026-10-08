"""bs_35: Koko eating bananas

Minimum eating speed k so Koko finishes all piles within h
hours (binary search on answer).

Time complexity: O(n log(max)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_35_VERSION = "bs-35.v1"


def min_eating_speed(piles, h):
    """Return the minimum integer speed to finish piles within h hours."""
    lo, hi = 1, max(piles)

    def hours(k):
        return sum((p + k - 1) // k for p in piles)

    while lo < hi:
        mid = (lo + hi) // 2
        if hours(mid) <= h:
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
    assert min_eating_speed([3, 6, 7, 11], 8) == 4
    assert min_eating_speed([30, 11, 23, 4, 20], 5) == 30
    assert min_eating_speed([30, 11, 23, 4, 20], 6) == 23
    assert min_eating_speed([1], 1) == 1
    assert stdlib_only()
    print("bs_35 OK")


if __name__ == "__main__":
    main()
