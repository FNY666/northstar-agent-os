"""Grid max flow (FLOW-042), Real."""
from __future__ import annotations
import ast

VERSION = "flow-42.v1"

def _dinic(n, edges, s, t):
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
    flow = 0
    INF = 10 ** 18
    while True:
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
            break
        it = [0] * n
        def dfs(u, f):
            if u == t:
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
        while True:
            f = dfs(s, INF)
            if f == 0:
                break
            flow += f
    return flow


def grid_max_flow(rows, cols, cap=1):
    n = rows * cols
    edges = []
    def idx(r, c):
        return r * cols + c
    for r in range(rows):
        for c in range(cols):
            if r + 1 < rows:
                edges.append((idx(r, c), idx(r + 1, c), cap))
                edges.append((idx(r + 1, c), idx(r, c), cap))
            if c + 1 < cols:
                edges.append((idx(r, c), idx(r, c + 1), cap))
                edges.append((idx(r, c + 1), idx(r, c), cap))
    return _dinic(n, edges, idx(0, 0), idx(rows - 1, cols - 1))

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
    assert grid_max_flow(2, 2) == 2
    assert grid_max_flow(1, 3) == 1
    assert grid_max_flow(3, 3) == 2
    assert stdlib_only()
    print("flow-42 OK")


if __name__ == "__main__":
    main()
