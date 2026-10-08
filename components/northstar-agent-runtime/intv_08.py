"""intv_08: Minimum arrows to burst all balloons (min_arrows).

Greedy by earliest end: one arrow at the end bursts every overlapping balloon.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_08 = "intv-08.v1"


def min_arrows(points):
    """Return minimum arrows so each balloon is burst."""
    if not points:
        return 0
    pts = sorted(points, key=lambda x: x[1])
    arrows = 1
    pos = pts[0][1]
    for s, e in pts[1:]:
        if s > pos:
            arrows += 1
            pos = e
    return arrows

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
    assert min_arrows([(10, 16), (2, 8), (1, 6), (7, 12)]) == 2
    assert min_arrows([(1, 2), (3, 4), (5, 6), (7, 8)]) == 4
    assert min_arrows([(1, 2), (2, 3), (3, 4), (4, 5)]) == 2
    assert min_arrows([]) == 0
    assert min_arrows([(1, 10)]) == 1
    assert stdlib_only()
    print("intv_08 OK")


if __name__ == "__main__":
    main()
