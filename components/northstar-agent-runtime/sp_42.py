"""Network delay time (max of shortest paths) (SP-042), Real."""
from __future__ import annotations
import ast

VERSION = "sp-42.v1"

import heapq
INF = float("inf")

def network_delay(n, edges, src):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        adj[u].append((v, w))
    dist = [INF] * n
    dist[src] = 0
    pq = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d != dist[u]:
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    mx = max(dist)
    return mx if mx < INF else -1

def main() -> None:
    assert network_delay(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1)], 0) == 3
    assert network_delay(3, [(0, 1, 1)], 0) == -1
    assert network_delay(1, [], 0) == 0
    assert network_delay(3, [(0, 1, 2), (0, 2, 5), (1, 2, 1)], 0) == 3
    assert stdlib_only()
    print("sp-42 OK")

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
