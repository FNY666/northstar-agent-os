"""intv_04: Check all meetings can be attended (can_attend).

Sort by start; any start earlier than the previous end means a conflict.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_04 = "intv-04.v1"


def can_attend(intervals):
    """True when no two intervals overlap."""
    ivs = sorted(intervals, key=lambda x: x[0])
    prev_end = float("-inf")
    for s, e in ivs:
        if s < prev_end:
            return False
        prev_end = max(prev_end, e)
    return True

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
    assert can_attend([(0, 30), (5, 10), (15, 20)]) is False
    assert can_attend([(7, 10), (2, 4)]) is True
    assert can_attend([]) is True
    assert can_attend([(5, 8), (8, 10)]) is True
    assert can_attend([(1, 5), (5, 6), (6, 7), (4, 5)]) is False
    assert stdlib_only()
    print("intv_04 OK")


if __name__ == "__main__":
    main()
