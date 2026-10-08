"""intv_18: Count intervals not covered by another (remove_covered).

Sort by start asc / end desc; an interval is covered when its end <= running max.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_18 = "intv-18.v1"


def remove_covered(intervals):
    """Return count of intervals not covered by any other."""
    ivs = sorted(intervals, key=lambda x: (x[0], -x[1]))
    count = 0
    max_end = -1
    for _, e in ivs:
        if e > max_end:
            count += 1
            max_end = e
    return count

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
    assert remove_covered([(1, 4), (3, 6), (2, 8)]) == 2
    assert remove_covered([(1, 4), (2, 3)]) == 1
    assert remove_covered([(0, 10), (3, 5), (3, 7)]) == 1
    assert remove_covered([(1, 2)]) == 1
    assert remove_covered([(1, 2), (1, 2), (1, 2)]) == 1
    assert stdlib_only()
    print("intv_18 OK")


if __name__ == "__main__":
    main()
