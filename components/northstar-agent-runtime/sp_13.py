"""SPFA queue-based shortest path (SP-013), Real."""
from __future__ import annotations
import ast

VERSION = "sp-13.v1"

from collections import deque
INF = float("inf")

def spfa(n, adj, src):
    dist = [INF] * n
    inq = [False] * n
    cnt = [0] * n
    dist[src] = 0
    q = deque([src])
    inq[src] = True
    while q:
        u = q.popleft()
        inq[u] = False
        for v, w in adj[u]:
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                if not inq[v]:
                    q.append(v)
                    inq[v] = True
                    cnt[v] += 1
                    if cnt[v] > n:
                        return None, True
    return dist, False

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    d, neg = spfa(4, adj, 0)
    assert neg is False and d == [0, 4, 1, 2]
    adjn = [[(1, 1)], [(2, -2)], []]
    d, neg = spfa(3, adjn, 0)
    assert neg is False and d == [0, 1, -1]
    adjc = [[(1, 1)], [(0, -2)]]
    d, neg = spfa(2, adjc, 0)
    assert neg is True
    adjd = [[(1, 1)], [], []]
    d, neg = spfa(3, adjd, 0)
    assert neg is False and d == [0, 1, INF]
    assert stdlib_only()
    print("sp-13 OK")

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
