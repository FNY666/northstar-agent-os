"""Lower bound flow feasibility (FLOW-041), Simulated."""
from __future__ import annotations
import ast

VERSION = "flow-41.v1"

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


def feasible_transport(n, edges, supply):
    SS, TT = n, n + 1
    N = n + 2
    aug = list(edges)
    tot = 0
    for v, s in enumerate(supply):
        if s > 0:
            aug.append((SS, v, s))
        elif s < 0:
            aug.append((v, TT, -s))
            tot += -s
    return _ek(N, aug, SS, TT) == tot

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
    assert feasible_transport(4, [(0,2,5),(0,3,5),(1,2,5),(1,3,5)], [4,3,-4,-3])
    assert not feasible_transport(4, [(0,2,1),(1,3,1)], [4,3,-4,-3])
    assert feasible_transport(2, [(0,1,5)], [5,-5])
    assert stdlib_only()
    print("flow-41 OK")


if __name__ == "__main__":
    main()
