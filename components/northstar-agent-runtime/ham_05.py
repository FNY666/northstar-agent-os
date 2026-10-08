"""Held-Karp DP Hamiltonian circuit (HAM-005), Real."""
from __future__ import annotations
import ast

VERSION = "ham-05.v1"

def _okc(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    c = path + [path[0]]
    return all((c[i], c[i + 1]) in s for i in range(n))

def hamiltonian_circuit_dp(n, edges):
    if n == 0:
        return []
    if n == 1:
        return [0]
    adjm = [[False] * n for _ in range(n)]
    for u, v in edges:
        adjm[u][v] = True
        adjm[v][u] = True
    N = 1 << n
    dp = [[-1] * n for _ in range(N)]
    for v in range(1, n):
        if adjm[0][v]:
            dp[1 | (1 << v)][v] = 0
    for mask in range(N):
        for u in range(n):
            if dp[mask][u] < 0:
                continue
            for v in range(n):
                if not (mask >> v) & 1 and adjm[u][v] and dp[mask | (1 << v)][v] < 0:
                    dp[mask | (1 << v)][v] = u
    full = N - 1
    for u in range(1, n):
        if dp[full][u] >= 0 and adjm[u][0]:
            path = []
            cur = u
            mask = full
            while True:
                path.append(cur)
                prev = dp[mask][cur]
                mask ^= (1 << cur)
                if prev < 0:
                    break
                cur = prev
            path.reverse()
            return path
    return []

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    assert _okc(3, tri, hamiltonian_circuit_dp(3, tri))
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert _okc(4, sq, hamiltonian_circuit_dp(4, sq))
    k5 = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    assert _okc(5, k5, hamiltonian_circuit_dp(5, k5))
    assert hamiltonian_circuit_dp(4, [(0, 1), (1, 2), (2, 3)]) == []
    assert hamiltonian_circuit_dp(0, []) == []
    assert stdlib_only()
    print('ham-05.v1 OK')
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
