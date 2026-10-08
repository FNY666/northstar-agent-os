"""intv_02: Insert one interval into a sorted disjoint list (insert_interval).

Walk the list, merging while overlapping the new interval, appending the rest.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_02 = "intv-02.v1"


def insert_interval(intervals, new):
    """Insert ``new`` into sorted disjoint ``intervals`` and merge overlaps."""
    res = []
    ns, ne = new
    i, n = 0, len(intervals)
    while i < n and intervals[i][1] < ns:
        res.append(intervals[i]); i += 1
    while i < n and intervals[i][0] <= ne:
        ns = min(ns, intervals[i][0]); ne = max(ne, intervals[i][1]); i += 1
    res.append((ns, ne))
    res.extend(intervals[i:])
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
    assert insert_interval([(1, 3), (6, 9)], (2, 5)) == [(1, 5), (6, 9)]
    assert insert_interval([(1, 2), (3, 5), (6, 7), (8, 10), (12, 16)], (4, 8)) == [(1, 2), (3, 10), (12, 16)]
    assert insert_interval([], (5, 7)) == [(5, 7)]
    assert insert_interval([(1, 5)], (2, 3)) == [(1, 5)]
    assert insert_interval([(1, 5)], (6, 8)) == [(1, 5), (6, 8)]
    assert stdlib_only()
    print("intv_02 OK")


if __name__ == "__main__":
    main()
