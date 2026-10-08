"""Manhattan MST via complete graph (exact O(n^2)) (MST-047), Real."""
from __future__ import annotations
import ast

VERSION = "mst-47.v1"

def manhattan_mst(points):
    n = len(points)
    edges = []
    for i in range(n):
        for j in range(i + 1, n):
            w = abs(points[i][0] - points[j][0]) + abs(points[i][1] - points[j][1])
            edges.append((i, j, w))
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0
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
    t, m = manhattan_mst([(0, 0), (1, 0), (1, 1), (0, 1)])
    assert t == 3 and len(m) == 3
    t, m = manhattan_mst([(0, 0), (2, 3)])
    assert t == 5
    t, m = manhattan_mst([(5, 5)])
    assert t == 0 and m == []
    assert stdlib_only()
    print("mst-47 OK")


if __name__ == "__main__":
    main()
