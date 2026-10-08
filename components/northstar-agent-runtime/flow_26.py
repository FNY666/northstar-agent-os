"""Konig bipartite vertex cover (FLOW-026), Simulated."""
from __future__ import annotations
import ast

VERSION = "flow-26.v1"

def max_matching(n_left, n_right, edges):
    from collections import deque
    adj = [[] for _ in range(n_left)]
    for u, v in edges:
        if 0 <= u < n_left and 0 <= v < n_right:
            adj[u].append(v)
    INF = 10 ** 9
    pair_u = [-1] * n_left
    pair_v = [-1] * n_right
    dist = [0] * n_left
    def bfs():
        q = deque()
        for u in range(n_left):
            if pair_u[u] == -1:
                dist[u] = 0
                q.append(u)
            else:
                dist[u] = INF
        found = False
        while q:
            u = q.popleft()
            for v in adj[u]:
                pu = pair_v[v]
                if pu != -1 and dist[pu] == INF:
                    dist[pu] = dist[u] + 1
                    q.append(pu)
                elif pu == -1:
                    found = True
        return found
    def dfs(u):
        for v in adj[u]:
            pu = pair_v[v]
            if pu == -1 or (dist[pu] == dist[u] + 1 and dfs(pu)):
                pair_u[u] = v
                pair_v[v] = u
                return True
        dist[u] = INF
        return False
    m = 0
    while bfs():
        for u in range(n_left):
            if pair_u[u] == -1 and dfs(u):
                m += 1
    return m

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
    assert max_matching(2, 2, [(0,0),(0,1),(1,0),(1,1)]) == 2
    assert max_matching(2, 2, [(0,0),(0,1),(1,1)]) == 2
    assert max_matching(3, 3, []) == 0
    assert max_matching(1, 3, [(0,2)]) == 1
    assert stdlib_only()
    print("flow-26 OK")


if __name__ == "__main__":
    main()
