"""Minimax path (minimize maximum edge weight) (SP-036), Real."""
from __future__ import annotations
import ast

VERSION = "sp-36.v1"

import heapq
INF = float("inf")

def minimax_path(n, adj, src, dst):
    best = [INF] * n
    best[src] = 0
    pq = [(0, src)]
    while pq:
        b, u = heapq.heappop(pq)
        if b != best[u]:
            continue
        if u == dst:
            return b
        for v, w in adj[u]:
            nb = max(b, w)
            if nb < best[v]:
                best[v] = nb
                heapq.heappush(pq, (nb, v))
    return best[dst]

def main() -> None:
    adj = [[(1, 5), (2, 1)], [(3, 5)], [(3, 1)], []]
    assert minimax_path(4, adj, 0, 3) == 1
    adj2 = [[(1, 9)], [(2, 9)], []]
    assert minimax_path(3, adj2, 0, 2) == 9
    assert minimax_path(3, [[(1, 1)], [], []], 0, 2) == INF
    assert minimax_path(1, [[]], 0, 0) == 0
    assert stdlib_only()
    print("sp-36 OK")

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
