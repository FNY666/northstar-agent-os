"""intv_03: Minimum removals for non-overlapping intervals (erase_overlap).

Greedy by earliest end: keep the interval that finishes first.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_03 = "intv-03.v1"


def erase_overlap(intervals):
    """Return minimum removals so remaining intervals do not overlap."""
    if not intervals:
        return 0
    ivs = sorted(intervals, key=lambda x: x[1])
    kept_end = ivs[0][1]
    removed = 0
    for s, e in ivs[1:]:
        if s < kept_end:
            removed += 1
        else:
            kept_end = e
    return removed

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
    assert erase_overlap([(1, 2), (2, 3), (3, 4), (1, 3)]) == 1
    assert erase_overlap([(1, 2), (1, 2), (1, 2)]) == 2
    assert erase_overlap([(1, 2), (2, 3)]) == 0
    assert erase_overlap([]) == 0
    assert erase_overlap([(1, 100), (11, 22), (1, 11), (2, 12)]) == 2
    assert stdlib_only()
    print("intv_03 OK")


if __name__ == "__main__":
    main()
