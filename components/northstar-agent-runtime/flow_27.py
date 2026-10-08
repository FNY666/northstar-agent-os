"""Maximum density subgraph (FLOW-027), Simulated."""
from __future__ import annotations
import ast

VERSION = "flow-27.v1"

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


def all_pairs_mincut(n, edges):
    # SIMULATED Gomory-Hu: pairwise min-cuts are exact; tree assembly omitted.
    bidir = []
    for u, v in edges:
        bidir.append((u, v, 1))
        bidir.append((v, u, 1))
    cuts = {}
    for i in range(n):
        for j in range(i + 1, n):
            cuts[(i, j)] = _ek(n, bidir, i, j)
    return cuts

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
    c = all_pairs_mincut(3, [(0,1),(1,2)])
    assert c[(0,1)] == 1 and c[(1,2)] == 1 and c[(0,2)] == 1
    c = all_pairs_mincut(4, [(0,1),(1,2),(2,3),(3,0)])
    assert c[(0,2)] == 2
    assert all(v >= 0 for v in c.values())
    assert stdlib_only()
    print("flow-27 OK")


if __name__ == "__main__":
    main()
