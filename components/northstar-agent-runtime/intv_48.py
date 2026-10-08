"""intv_48: Maximum overlap depth of intervals (max_overlap_depth).

Sweep line: +1 at start, -1 after end; track the peak.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_48 = "intv-48.v1"


def max_overlap_depth(intervals):
    """Largest number of intervals covering any single point."""
    events = []
    for s, e in intervals:
        events.append((s, 1)); events.append((e, -1))
    events.sort(key=lambda x: (x[0], -x[1]))
    cur = best = 0
    for _, d in events:
        cur += d
        if cur > best:
            best = cur
    return best

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
    assert max_overlap_depth([(1, 4), (2, 5), (7, 9)]) == 2
    assert max_overlap_depth([(6, 7), (2, 4), (8, 12)]) == 1
    assert max_overlap_depth([(1, 10), (2, 9), (3, 8)]) == 3
    assert max_overlap_depth([]) == 0
    assert max_overlap_depth([(1, 2), (2, 3), (3, 4)]) == 2
    assert stdlib_only()
    print("intv_48 OK")


if __name__ == "__main__":
    main()
