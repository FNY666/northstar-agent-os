"""0-1 BFS (SP-010), Real."""
from __future__ import annotations
import ast

VERSION = "sp-10.v1"

from collections import deque
INF = float("inf")

def zero_one_bfs(n, adj, src):
    dist = [INF] * n
    dist[src] = 0
    dq = deque([src])
    while dq:
        u = dq.popleft()
        for v, w in adj[u]:
            nd = dist[u] + w
            if nd < dist[v]:
                dist[v] = nd
                if w == 0:
                    dq.appendleft(v)
                else:
                    dq.append(v)
    return dist

def main() -> None:
    adj = [[(1, 0), (2, 1)], [(3, 1)], [(3, 0)], []]
    assert zero_one_bfs(4, adj, 0) == [0, 0, 1, 1]
    adj2 = [[(1, 1)], [(2, 1)], []]
    assert zero_one_bfs(3, adj2, 0) == [0, 1, 2]
    adj3 = [[(1, 0)], [(2, 0)], []]
    assert zero_one_bfs(3, adj3, 0) == [0, 0, 0]
    adj4 = [[(1, 1)], [], []]
    assert zero_one_bfs(3, adj4, 0) == [0, 1, INF]
    assert stdlib_only()
    print("sp-10 OK")

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
