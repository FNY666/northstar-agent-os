"""Euclidean MST via complete graph (exact O(n^2)) (MST-043), Real."""
from __future__ import annotations
import ast
import math
VERSION = "mst-43.v1"

def euclidean_mst(points):
    n = len(points)
    edges = []
    for i in range(n):
        for j in range(i + 1, n):
            dx = points[i][0] - points[j][0]
            dy = points[i][1] - points[j][1]
            edges.append((i, j, math.hypot(dx, dy)))
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0.0
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            total += w
            mst.append((u, v, w))
            if len(mst) == n - 1:
                break
    return total, mst

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    t, m = euclidean_mst([(0, 0), (1, 0), (1, 1), (0, 1)])
    assert abs(t - 3.0) < 1e-9 and len(m) == 3
    t, m = euclidean_mst([(0, 0), (3, 4)])
    assert abs(t - 5.0) < 1e-9
    t, m = euclidean_mst([(0, 0)])
    assert t == 0.0 and m == []
    assert stdlib_only()
    print("mst-43 OK")


if __name__ == "__main__":
    main()
