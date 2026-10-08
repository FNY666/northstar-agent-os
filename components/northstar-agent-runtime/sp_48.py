"""K shortest walks (visit-count Dijkstra) (SP-048), Real."""
from __future__ import annotations
import ast

VERSION = "sp-48.v1"

import heapq
INF = float("inf")

def k_shortest_walks(n, adj, src, dst, k):
    cnt = [0] * n
    pq = [(0, src)]
    res = []
    while pq and len(res) < k:
        d, u = heapq.heappop(pq)
        cnt[u] += 1
        if cnt[u] > k:
            continue
        if u == dst:
            res.append(d)
        for v, w in adj[u]:
            heapq.heappush(pq, (d + w, v))
    return res

def main() -> None:
    adj = [[(1, 1), (2, 2)], [(3, 1)], [(3, 1)], []]
    assert k_shortest_walks(4, adj, 0, 3, 2) == [2, 3]
    assert k_shortest_walks(4, adj, 0, 3, 1) == [2]
    tri = [[(1, 1), (2, 5)], [(2, 1)], []]
    assert k_shortest_walks(3, tri, 0, 2, 2) == [2, 5]
    assert k_shortest_walks(3, [[(1, 1)], [], []], 0, 2, 2) == []
    assert stdlib_only()
    print("sp-48 OK")

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
