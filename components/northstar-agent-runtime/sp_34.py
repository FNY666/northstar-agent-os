"""Greedy best-first search (SP-034), Real."""
from __future__ import annotations
import ast

VERSION = "sp-34.v1"

import heapq
INF = float("inf")

def greedy_bfs(n, adj, src, dst, h):
    visited = [False] * n
    pq = [(h(src), src)]
    visited[src] = True
    steps = 0
    while pq:
        _, u = heapq.heappop(pq)
        steps += 1
        if u == dst:
            return True, steps
        for v, w in adj[u]:
            if not visited[v]:
                visited[v] = True
                heapq.heappush(pq, (h(v), v))
    return False, steps

def main() -> None:
    adj = [[(1, 1), (2, 1)], [(3, 1)], [(3, 1)], []]
    h = {0: 2, 1: 1, 2: 1, 3: 0}
    ok, _ = greedy_bfs(4, adj, 0, 3, lambda v: h[v])
    assert ok is True
    ok, _ = greedy_bfs(4, adj, 3, 0, lambda v: h[v])
    assert ok is False
    ok, _ = greedy_bfs(1, [[]], 0, 0, lambda v: 0)
    assert ok is True
    line = [[(1, 1)], [(2, 1)], []]
    ok, s = greedy_bfs(3, line, 0, 2, lambda v: 2 - v)
    assert ok is True and s == 3
    assert stdlib_only()
    print("sp-34 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
