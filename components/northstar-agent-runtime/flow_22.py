"""Node-capacitated max flow (FLOW-022), Real."""
from __future__ import annotations
import ast

VERSION = "flow-22.v1"

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


def max_flow_node_caps(n, edges, node_cap, s, t):
    N = 2 * n
    INF = 10 ** 15
    aug = []
    for v in range(n):
        c = node_cap[v] if v != s and v != t else INF
        aug.append((2 * v, 2 * v + 1, c))
    for u, v, c in edges:
        aug.append((2 * u + 1, 2 * v, c))
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
    assert max_flow_node_caps(3, [(0,1,10),(1,2,10)], [0,3,0], 0, 2) == 3
    assert max_flow_node_caps(3, [(0,1,10),(1,2,10)], [0,10,0], 0, 2) == 10
    assert max_flow_node_caps(4, [(0,1,5),(0,2,5),(1,3,5),(2,3,5)], [0,2,2,0], 0, 3) == 4
    assert stdlib_only()
    print("flow-22 OK")


if __name__ == "__main__":
    main()
