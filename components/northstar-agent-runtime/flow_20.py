"""Vertex-disjoint paths (FLOW-020), Real."""
from __future__ import annotations
import ast

VERSION = "flow-20.v1"

def _ek(n, edges, s, t):
    from collections import deque
    g = [[] for _ in range(n)]
    def add_edge(u, v, c):
        g[u].append([v, c, len(g[v])])
        g[v].append([u, 0, len(g[u]) - 1])
    for u, v, c in edges:
        if u != v and c > 0:
            add_edge(u, v, c)
    flow = 0
    INF = 10 ** 18
    while True:
        par = [(-1, -1)] * n
        par[s] = (s, -1)
        q = deque([s])
        while q:
            u = q.popleft()
            for i, e in enumerate(g[u]):
                v, c = e[0], e[1]
                if c > 0 and par[v][0] == -1:
                    par[v] = (u, i)
                    q.append(v)
        if par[t][0] == -1:
            break
        f = INF
        v = t
        while v != s:
            u, i = par[v]
            f = min(f, g[u][i][1])
            v = u
        v = t
        while v != s:
            u, i = par[v]
            g[u][i][1] -= f
            g[v][g[u][i][2]][1] += f
            v = u
        flow += f
    return flow


def vertex_disjoint_paths(n, arcs, s, t):
    N = 2 * n
    INF = 10 ** 9
    aug = []
    for v in range(n):
        cap = INF if v == s or v == t else 1
        aug.append((2 * v, 2 * v + 1, cap))
    for u, v in arcs:
        aug.append((2 * u + 1, 2 * v, 1))
    return _ek(N, aug, 2 * s, 2 * t + 1)

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
    assert vertex_disjoint_paths(4, [(0,1),(0,2),(1,3),(2,3)], 0, 3) == 2
    assert vertex_disjoint_paths(4, [(0,1),(1,2),(2,3)], 0, 3) == 1
    assert vertex_disjoint_paths(3, [(0,1)], 0, 2) == 0
    assert stdlib_only()
    print("flow-20 OK")


if __name__ == "__main__":
    main()
