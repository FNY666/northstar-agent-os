"""Widest path (maximize minimum edge weight) (SP-038), Real."""
from __future__ import annotations
import ast

VERSION = "sp-38.v1"

import heapq
NINF = float("-inf")

def widest_path(n, adj, src, dst):
    best = [NINF] * n
    best[src] = float("inf")
    pq = [(-best[src], src)]
    while pq:
        nb, u = heapq.heappop(pq)
        nb = -nb
        if nb != best[u]:
            continue
        for v, w in adj[u]:
            cand = min(nb, w)
            if cand > best[v]:
                best[v] = cand
                heapq.heappush(pq, (-cand, v))
    return best[dst] if best[dst] != NINF else NINF

def main() -> None:
    adj = [[(1, 5), (2, 1)], [(3, 5)], [(3, 8)], []]
    assert widest_path(4, adj, 0, 3) == 5
    adj2 = [[(1, 3)], [(2, 4)], []]
    assert widest_path(3, adj2, 0, 2) == 3
    assert widest_path(3, [[(1, 1)], [], []], 0, 2) == NINF
    assert widest_path(1, [[]], 0, 0) == float("inf")
    assert stdlib_only()
    print("sp-38 OK")

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
