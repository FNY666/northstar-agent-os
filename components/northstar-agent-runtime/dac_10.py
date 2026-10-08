"""dac-10: Closest pair of points.

O(n log n) divide and conquer: split by x, recurse, check the strip. Returns squared distance.
"""
import ast
import sys

DAC_10_VERSION = "dac-10.v1"

def _dist2(p, q):
    return (p[0] - q[0]) ** 2 + (p[1] - q[1]) ** 2


def _closest(px, py):
    n = len(px)
    if n <= 3:
        best = float("inf")
        for i in range(n):
            for j in range(i + 1, n):
                d = _dist2(px[i], px[j])
                if d < best:
                    best = d
        return best
    mid = n // 2
    midx = px[mid][0]
    left_ids = set(map(id, px[:mid]))
    pyl = [p for p in py if id(p) in left_ids]
    pyr = [p for p in py if id(p) not in left_ids]
    d = min(_closest(px[:mid], pyl), _closest(px[mid:], pyr))
    strip = [p for p in py if (p[0] - midx) ** 2 < d]
    for i in range(len(strip)):
        for j in range(i + 1, min(i + 8, len(strip))):
            dd = _dist2(strip[i], strip[j])
            if dd < d:
                d = dd
    return d


def closest_pair(points):
    """Squared distance of the closest pair (divide and conquer)."""
    pts = list(points)
    if len(pts) < 2:
        raise ValueError("need at least two points")
    px = sorted(pts, key=lambda p: p[0])
    py = sorted(pts, key=lambda p: p[1])
    return _closest(px, py)

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
    assert closest_pair([(0, 0), (3, 4)]) == 25
    assert closest_pair([(0, 0), (1, 1), (5, 5)]) == 2
    assert closest_pair([(2, 2), (2, 2), (9, 9)]) == 0
    assert closest_pair([(0, 0), (0, 5), (0, 2)]) == 4
    try:
        closest_pair([(1, 1)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-10 OK")


if __name__ == "__main__":
    main()
