"""Count Hamiltonian circuits via DP (HAM-022), Real."""
from __future__ import annotations
import ast

VERSION = "ham-22.v1"

def count_ham_circuits(n, edges):
    if n < 3:
        return 0
    adjm = [[False] * n for _ in range(n)]
    for u, v in edges:
        adjm[u][v] = True
        adjm[v][u] = True
    N = 1 << n
    dp = [[0] * n for _ in range(N)]
    dp[1][0] = 1
    for mask in range(N):
        if not mask & 1:
            continue
        for u in range(n):
            c = dp[mask][u]
            if not c:
                continue
            for v in range(1, n):
                if not (mask >> v) & 1 and adjm[u][v]:
                    dp[mask | (1 << v)][v] += c
    full = N - 1
    total = sum(dp[full][u] for u in range(1, n) if adjm[u][0])
    return total // 2

def main() -> None:
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert count_ham_circuits(4, k4) == 3
    tri = [(0, 1), (1, 2), (2, 0)]
    assert count_ham_circuits(3, tri) == 1
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert count_ham_circuits(4, sq) == 1
    assert count_ham_circuits(4, [(0, 1), (1, 2), (2, 3)]) == 0
    assert count_ham_circuits(2, [(0, 1)]) == 0
    assert stdlib_only()
    print('ham-22.v1 OK')
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
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
