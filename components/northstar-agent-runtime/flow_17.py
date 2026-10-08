"""Max weight closure project selection (FLOW-017), Real."""
from __future__ import annotations
import ast

VERSION = "flow-17.v1"

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


def max_closure(n, prec, weights):
    SS, TT = n, n + 1
    N = n + 2
    aug = []
    pos = 0
    for v, w in enumerate(weights):
        if w > 0:
            aug.append((SS, v, w))
            pos += w
        elif w < 0:
            aug.append((v, TT, -w))
    INF = sum(abs(w) for w in weights) + 1
    for u, v in prec:
        aug.append((u, v, INF))
    return pos - _ek(N, aug, SS, TT)

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
    assert max_closure(3, [(0,1)], [5,-3,2]) == 4
    assert max_closure(2, [], [4,-1]) == 4
    assert max_closure(2, [(0,1)], [-5,10]) == 10
    assert stdlib_only()
    print("flow-17 OK")


if __name__ == "__main__":
    main()
