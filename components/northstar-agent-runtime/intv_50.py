"""intv_50: Total length covered by union of intervals (union_length).

Merge sorted intervals, then sum end - start.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_50 = "intv-50.v1"


def union_length(intervals):
    """Total length of the union of [start, end) intervals."""
    if not intervals:
        return 0
    ivs = sorted(intervals, key=lambda x: x[0])
    total = 0
    cs, ce = ivs[0]
    for s, e in ivs[1:]:
        if s <= ce:
            if e > ce:
                ce = e
        else:
            total += ce - cs
            cs, ce = s, e
    total += ce - cs
    return total

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
    assert union_length([(1, 4), (2, 5), (7, 9)]) == 6
    assert union_length([(1, 2), (3, 4)]) == 2
    assert union_length([]) == 0
    assert union_length([(0, 10)]) == 10
    assert union_length([(1, 5), (5, 10)]) == 9
    assert stdlib_only()
    print("intv_50 OK")


if __name__ == "__main__":
    main()
