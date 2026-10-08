"""intv_06: Intersection of two interval lists (interval_intersection).

Two pointers advance the interval that ends first.

Time complexity: O(m + n) time
Space complexity: O(m + n) auxiliary
"""

import ast
import sys

INTV_06 = "intv-06.v1"


def interval_intersection(a, b):
    """Return pairwise intersections of two disjoint sorted lists."""
    i = j = 0
    res = []
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0]); hi = min(a[i][1], b[j][1])
        if lo <= hi:
            res.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return res

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
    assert interval_intersection([(0, 2), (5, 10), (13, 23), (24, 25)], [(1, 5), (8, 12), (15, 24), (25, 26)]) == [(1, 2), (5, 5), (8, 10), (15, 23), (24, 24), (25, 25)]
    assert interval_intersection([(1, 3), (5, 9)], []) == []
    assert interval_intersection([(1, 7)], [(3, 10)]) == [(3, 7)]
    assert interval_intersection([(1, 2)], [(3, 4)]) == []
    assert interval_intersection([(0, 0)], [(0, 0)]) == [(0, 0)]
    assert stdlib_only()
    print("intv_06 OK")


if __name__ == "__main__":
    main()
