"""Minimax path with reconstruction (SP-037), Real."""
from __future__ import annotations
import ast

VERSION = "sp-37.v1"

import heapq
INF = float("inf")

def minimax_path_rec(n, adj, src, dst):
    best = [INF] * n
    parent = [-1] * n
    best[src] = 0
    pq = [(0, src)]
    while pq:
        b, u = heapq.heappop(pq)
        if b != best[u]:
            continue
        for v, w in adj[u]:
            nb = max(b, w)
            if nb < best[v]:
                best[v] = nb
                parent[v] = u
                heapq.heappush(pq, (nb, v))
    if best[dst] == INF:
        return INF, []
    path = []
    cur = dst
    while cur != -1:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return best[dst], path

def main() -> None:
    adj = [[(1, 5), (2, 1)], [(3, 5)], [(3, 1)], []]
    b, p = minimax_path_rec(4, adj, 0, 3)
    assert b == 1 and p == [0, 2, 3]
    b, p = minimax_path_rec(3, [[(1, 1)], [], []], 0, 2)
    assert b == INF and p == []
    b, p = minimax_path_rec(1, [[]], 0, 0)
    assert b == 0 and p == [0]
    b, p = minimax_path_rec(3, [[(1, 9)], [(2, 9)], []], 0, 2)
    assert b == 9 and p == [0, 1, 2]
    assert stdlib_only()
    print("sp-37 OK")

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
