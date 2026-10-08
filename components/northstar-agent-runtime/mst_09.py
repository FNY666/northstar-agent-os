"""Kruskal minimum spanning forest (disconnected graphs) (MST-009), Real."""
from __future__ import annotations
import ast

VERSION = "mst-09.v1"

def kruskal_forest(n, edges):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    forest = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            forest.append((u, v, w))
    comps = len({find(i) for i in range(n)})
    return sum(x[2] for x in forest), forest, comps

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
    t, f, c = kruskal_forest(4, [(0, 1, 5), (2, 3, 7)])
    assert t == 12 and c == 2 and len(f) == 2
    t, f, c = kruskal_forest(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and c == 1
    t, f, c = kruskal_forest(3, [])
    assert t == 0 and c == 3 and f == []
    assert stdlib_only()
    print("mst-09 OK")


if __name__ == "__main__":
    main()
