"""Stoer-Wagner global min cut (FLOW-024), Real."""
from __future__ import annotations
import ast

VERSION = "flow-24.v1"

def global_min_cut(n, edges):
    adj = [[0] * n for _ in range(n)]
    for e in edges:
        u, v = e[0], e[1]
        w = e[2] if len(e) > 2 else 1
        adj[u][v] += w
        adj[v][u] += w
    verts = list(range(n))
    best = float("inf")
    while len(verts) > 1:
        added = [False] * n
        w = [0] * n
        prev = -1
        order = 0
        for _ in range(len(verts)):
            sel = -1
            for v in verts:
                if not added[v] and (sel == -1 or w[v] > w[sel]):
                    sel = v
            added[sel] = True
            order += 1
            if order == len(verts):
                if w[sel] < best:
                    best = w[sel]
                for v in verts:
                    adj[prev][v] += adj[sel][v]
                    adj[v][prev] += adj[v][sel]
                verts.remove(sel)
                break
            prev = sel
            for v in verts:
                if not added[v]:
                    w[v] += adj[sel][v]
    return best

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections",
               "math", "itertools", "functools", "random", "sys", "copy"}
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
    assert global_min_cut(3, [(0,1,1),(1,2,1),(2,0,1)]) == 2
    assert global_min_cut(4, [(0,1,1),(1,2,1),(2,3,1),(3,0,1)]) == 2
    assert global_min_cut(3, [(0,1,5),(1,2,1),(0,2,1)]) == 2
    assert stdlib_only()
    print("flow-24 OK")


if __name__ == "__main__":
    main()
