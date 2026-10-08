"""Shortest Hamiltonian path (Held-Karp bitmask DP) (SP-050), Real."""
from __future__ import annotations
import ast

VERSION = "sp-50.v1"

INF = float("inf")

def tsp_path(n, mat, src):
    size = 1 << n
    dp = [[INF] * n for _ in range(size)]
    dp[1 << src][src] = 0
    for mask in range(size):
        for u in range(n):
            if dp[mask][u] == INF:
                continue
            for v in range(n):
                if mask & (1 << v) or mat[u][v] == INF:
                    continue
                nm = mask | (1 << v)
                nd = dp[mask][u] + mat[u][v]
                if nd < dp[nm][v]:
                    dp[nm][v] = nd
    full = size - 1
    return min(dp[full])

def main() -> None:
    m = [[0, 10, 15], [10, 0, 35], [15, 35, 0]]
    assert tsp_path(3, m, 0) == 45
    m2 = [[0, 1, 1, 1], [1, 0, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0]]
    assert tsp_path(4, m2, 0) == 3
    assert tsp_path(1, [[0]], 0) == 0
    m3 = [[0, 2, INF], [INF, 0, 3], [INF, INF, 0]]
    assert tsp_path(3, m3, 0) == 5
    assert stdlib_only()
    print("sp-50 OK")

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
