"""dac-46: Convex hull (divide and conquer).

Split points by x, hull each half, merge hulls with a monotone chain. Simplified merge (mock).
"""
import ast
import sys

DAC_46_VERSION = "dac-46.v1"

def _cross(o, a, b):
    return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])


def _chain(points):
    pts = sorted(set(points))
    if len(pts) <= 1:
        return pts
    lower = []
    for p in pts:
        while len(lower) >= 2 and _cross(lower[-2], lower[-1], p) <= 0:
            lower.pop()
        lower.append(p)
    upper = []
    for p in reversed(pts):
        while len(upper) >= 2 and _cross(upper[-2], upper[-1], p) <= 0:
            upper.pop()
        upper.append(p)
    return lower[:-1] + upper[:-1]


def _hull_dc(pts):
    if len(pts) <= 8:
        return _chain(pts)
    mid = len(pts) // 2
    return _chain(_hull_dc(pts[:mid]) + _hull_dc(pts[mid:]))


def convex_hull_dc(points):
    """Convex hull via divide and conquer (simplified hull-merge)."""
    pts = sorted(set(points))
    if len(pts) <= 1:
        return pts
    return _hull_dc(pts)

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert convex_hull_dc([]) == []
    assert convex_hull_dc([(1, 1)]) == [(1, 1)]
    hull = convex_hull_dc([(0, 0), (0, 1), (1, 0), (1, 1), (0.5, 0.5)])
    assert sorted(hull) == [(0, 0), (0, 1), (1, 0), (1, 1)]
    hull2 = convex_hull_dc([(0, 0), (2, 0), (1, 1), (1, -1), (3, 0)])
    assert (0, 0) in hull2 and (3, 0) in hull2 and (1, 1) in hull2 and (1, -1) in hull2
    assert stdlib_only()
    print("dac-46 OK")


if __name__ == "__main__":
    main()
