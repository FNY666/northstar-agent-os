"""intv_01: Merge overlapping intervals (merge_intervals).

Sort by start, then sweep merging any interval that overlaps the running one.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_01 = "intv-01.v1"


def merge_intervals(intervals):
    """Merge all overlapping intervals, return list of disjoint intervals."""
    if not intervals:
        return []
    ivs = sorted(intervals, key=lambda x: x[0])
    merged = [list(ivs[0])]
    for s, e in ivs[1:]:
        if s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    return [tuple(m) for m in merged]

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
    assert merge_intervals([(1, 3), (2, 6), (8, 10), (15, 18)]) == [(1, 6), (8, 10), (15, 18)]
    assert merge_intervals([(1, 4), (4, 5)]) == [(1, 5)]
    assert merge_intervals([]) == []
    assert merge_intervals([(1, 4), (0, 0)]) == [(0, 0), (1, 4)]
    assert merge_intervals([(1, 4), (2, 3)]) == [(1, 4)]
    assert stdlib_only()
    print("intv_01 OK")


if __name__ == "__main__":
    main()
