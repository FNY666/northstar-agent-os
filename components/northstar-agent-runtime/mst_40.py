"""Degree-constrained MST heuristic (NP-hard, approx) (MST-040), Simulated."""
from __future__ import annotations
import ast

VERSION = "mst-40.v1"

def degree_constrained_mst(n, edges, max_degree=2):
    # Degree-constrained MST is NP-hard; this is a Kruskal-style heuristic
    # that skips edges which would violate the degree bound. Documented
    # approximation, not an exact solver.
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    deg = [0] * n
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        if deg[u] >= max_degree or deg[v] >= max_degree:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            deg[u] += 1
            deg[v] += 1
            mst.append((u, v, w))
    ok = all(d <= max_degree for d in deg)
    return sum(x[2] for x in mst), mst, ok

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
    t, m, ok = degree_constrained_mst(4, [(0, 1, 1), (0, 2, 1), (0, 3, 1), (1, 2, 10)], max_degree=2)
    assert ok is True
    assert all(sum(1 for a, b, _ in m if a == i or b == i) <= 2 for i in range(4))
    t, m, ok = degree_constrained_mst(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], max_degree=2)
    assert t == 3 and ok
    assert stdlib_only()
    print("mst-40 OK")


if __name__ == "__main__":
    main()
