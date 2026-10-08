"""Ford-Fulkerson DFS augmenting path (FLOW-003), Real."""
from __future__ import annotations
import ast

VERSION = "flow-03.v1"

def max_flow(n, edges, s, t):
    import sys
    sys.setrecursionlimit(10000)
    g = [[] for _ in range(n)]
    def add_edge(u, v, c):
        g[u].append([v, c, len(g[v])])
        g[v].append([u, 0, len(g[u]) - 1])
    for u, v, c in edges:
        if u != v and c > 0:
            add_edge(u, v, c)
    flow = 0
    INF = 10 ** 18
    def dfs(u, f, seen):
        if u == t:
            return f
        seen.add(u)
        for e in g[u]:
            v, c, rev = e
            if c > 0 and v not in seen:
                ret = dfs(v, min(f, c), seen)
                if ret > 0:
                    e[1] -= ret
                    g[v][rev][1] += ret
                    return ret
        return 0
    while True:
        f = dfs(s, INF, set())
        if f == 0:
            break
        flow += f
    return flow

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
    assert max_flow(6, g1, 0, 5) == 23
    assert max_flow(4, [(0,1,3),(0,2,3),(1,3,3),(2,3,3)], 0, 3) == 6
    assert max_flow(2, [(0,1,7)], 0, 1) == 7
    assert max_flow(3, [(0,1,5)], 0, 2) == 0
    assert stdlib_only()
    print("flow-03 OK")


if __name__ == "__main__":
    main()
