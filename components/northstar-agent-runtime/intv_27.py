"""intv_27: Union area of rectangles (rect_union_area).

Sweep x; at each slab multiply width by merged y-coverage.

Time complexity: O(n^2) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_27 = "intv-27.v1"


def rect_union_area(rects):
    """Total area covered by [x1, y1, x2, y2] rectangles."""
    if not rects:
        return 0
    xs = sorted({x for r in rects for x in (r[0], r[2])})
    area = 0
    for i in range(len(xs) - 1):
        x0, x1 = xs[i], xs[i + 1]
        width = x1 - x0
        if width == 0:
            continue
        ys = []
        for rx1, ry1, rx2, ry2 in rects:
            if rx1 <= x0 and rx2 >= x1:
                ys.append((ry1, ry2))
        ys.sort()
        cy = 0
        cs = ce = None
        for s, e in ys:
            if cs is None:
                cs, ce = s, e
            elif s <= ce:
                ce = max(ce, e)
            else:
                cy += ce - cs
                cs, ce = s, e
        if cs is not None:
            cy += ce - cs
        area += width * cy
    return area

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
    assert rect_union_area([(0, 0, 2, 2), (1, 0, 2, 3), (1, 0, 3, 1)]) == 6
    assert rect_union_area([(0, 0, 1000000000, 1000000000)]) == 1000000000000000000
    assert rect_union_area([]) == 0
    assert rect_union_area([(0, 0, 1, 1)]) == 1
    assert rect_union_area([(0, 0, 1, 1), (2, 2, 3, 3)]) == 2
    assert stdlib_only()
    print("intv_27 OK")


if __name__ == "__main__":
    main()
