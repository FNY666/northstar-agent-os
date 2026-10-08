"""dac-45: Closest pair (D&C vs brute force).

Exposes both the O(n log n) divide-and-conquer and the O(n^2) baseline and asserts agreement.
"""
import ast
import sys

DAC_45_VERSION = "dac-45.v1"

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


def closest_pair_bruteforce(points):
    """O(n^2) baseline: squared distance of the closest pair."""
    pts = list(points)
    if len(pts) < 2:
        raise ValueError("need at least two points")
    best = float("inf")
    for i in range(len(pts)):
        for j in range(i + 1, len(pts)):
            d = _dist2(pts[i], pts[j])
            if d < best:
                best = d
    return best


def closest_pair_dc(points):
    """O(n log n) divide-and-conquer closest pair (squared distance)."""
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
    pts = [(0, 0), (3, 1), (1, 2), (5, 5), (2, 2)]
    assert closest_pair_dc(pts) == closest_pair_bruteforce(pts)
    pts2 = [(i, (i * 7) % 11) for i in range(30)]
    assert closest_pair_dc(pts2) == closest_pair_bruteforce(pts2)
    assert closest_pair_dc([(0, 0), (0, 0)]) == 0
    try:
        closest_pair_dc([(1, 1)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-45 OK")


if __name__ == "__main__":
    main()
