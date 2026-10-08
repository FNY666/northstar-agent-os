"""Cheapest flights within K stops (SP-041), Real."""
from __future__ import annotations
import ast

VERSION = "sp-41.v1"

INF = float("inf")

def cheapest_flights(n, flights, src, dst, k):
    dist = [INF] * n
    dist[src] = 0
    for _ in range(k + 1):
        nd = dist[:]
        for u, v, w in flights:
            if dist[u] != INF and dist[u] + w < nd[v]:
                nd[v] = dist[u] + w
        dist = nd
    return dist[dst] if dist[dst] != INF else -1

def main() -> None:
    fl = [(0, 1, 100), (1, 2, 100), (0, 2, 500)]
    assert cheapest_flights(3, fl, 0, 2, 1) == 200
    assert cheapest_flights(3, fl, 0, 2, 0) == 500
    assert cheapest_flights(3, [(0, 1, 100)], 0, 2, 1) == -1
    assert cheapest_flights(3, fl, 0, 0, 2) == 0
    assert stdlib_only()
    print("sp-41 OK")

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
