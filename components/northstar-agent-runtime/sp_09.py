"""Dial's algorithm (bucket Dijkstra, small integer weights) (SP-009), Real."""
from __future__ import annotations
import ast

VERSION = "sp-09.v1"

from collections import deque
INF = float("inf")

def dial(n, adj, src, cmax):
    maxd = cmax * n
    dist = [INF] * n
    dist[src] = 0
    buckets = [deque() for _ in range(maxd + 1)]
    buckets[0].append(src)
    for d in range(maxd + 1):
        while buckets[d]:
            u = buckets[d].popleft()
            if dist[u] < d:
                continue
            for v, w in adj[u]:
                nd = d + w
                if nd < dist[v] and nd <= maxd:
                    dist[v] = nd
                    buckets[nd].append(v)
    return dist

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    assert dial(4, adj, 0, 5) == [0, 4, 1, 2]
    adj2 = [[(1, 3)], [(2, 3)], []]
    assert dial(3, adj2, 0, 3) == [0, 3, 6]
    assert dial(1, [[]], 0, 1) == [0]
    adj3 = [[(1, 2)], [], [(1, 1)]]
    assert dial(3, adj3, 0, 2) == [0, 2, INF]
    assert stdlib_only()
    print("sp-09 OK")

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
