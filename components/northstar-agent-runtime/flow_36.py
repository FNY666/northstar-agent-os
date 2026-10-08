"""Blocking flow phase (FLOW-036), Real."""
from __future__ import annotations
import ast

VERSION = "flow-36.v1"

def blocking_flow(n, edges, s, t):
    import sys
    from collections import deque
    sys.setrecursionlimit(10000)
    g = [[] for _ in range(n)]
    def add_edge(u, v, c):
        g[u].append([v, c, len(g[v])])
        g[v].append([u, 0, len(g[u]) - 1])
    for u, v, c in edges:
        if u != v and c > 0:
            add_edge(u, v, c)
    level = [-1] * n
    level[s] = 0
    q = deque([s])
    while q:
        u = q.popleft()
        for v, c, _ in g[u]:
            if c > 0 and level[v] == -1:
                level[v] = level[u] + 1
                q.append(v)
    if level[t] == -1:
        return 0
    it = [0] * n
    total = [0]
    def dfs(u, f):
        if u == t:
            total[0] += f
            return f
        while it[u] < len(g[u]):
            i = it[u]
            v, c, rev = g[u][i]
            if c > 0 and level[v] == level[u] + 1:
                ret = dfs(v, min(f, c))
                if ret > 0:
                    g[u][i][1] -= ret
                    g[v][rev][1] += ret
                    return ret
            it[u] += 1
        return 0
    INF = 10 ** 18
    while dfs(s, INF):
        pass
    return total[0]

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
    g1 = [(0,1,16),(0,2,13),(1,2,10),(1,3,12),(2,1,4),(2,4,14),(3,2,9),(3,5,20),(4,3,7),(4,5,4)]
    assert blocking_flow(6, g1, 0, 5) >= 1
    assert blocking_flow(4, [(0,1,3),(0,2,3),(1,3,3),(2,3,3)], 0, 3) == 6
    assert blocking_flow(3, [(0,1,5)], 0, 2) == 0
    assert stdlib_only()
    print("flow-36 OK")


if __name__ == "__main__":
    main()
