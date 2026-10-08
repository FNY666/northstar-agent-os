"""Held-Karp DP Hamiltonian path any endpoints (HAM-006), Real."""
from __future__ import annotations
import ast

VERSION = "ham-06.v1"

def _ok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def hamiltonian_path_dp(n, edges):
    adjm = [[False] * n for _ in range(n)]
    for u, v in edges:
        adjm[u][v] = True
        adjm[v][u] = True
    N = 1 << n
    prev = [[-1] * n for _ in range(N)]
    reach = [[False] * n for _ in range(N)]
    for v in range(n):
        reach[1 << v][v] = True
    for mask in range(N):
        for u in range(n):
            if not reach[mask][u]:
                continue
            for v in range(n):
                if not (mask >> v) & 1 and adjm[u][v] and not reach[mask | (1 << v)][v]:
                    reach[mask | (1 << v)][v] = True
                    prev[mask | (1 << v)][v] = u
    full = N - 1
    for v in range(n):
        if reach[full][v]:
            path = []
            cur = v
            mask = full
            while cur >= 0:
                path.append(cur)
                p = prev[mask][cur]
                mask ^= (1 << cur)
                cur = p
            path.reverse()
            return path
    return []

def main() -> None:
    e = [(0, 1), (1, 2), (2, 3)]
    assert _ok(4, e, hamiltonian_path_dp(4, e))
    star = [(0, 1), (0, 2), (0, 3)]
    assert hamiltonian_path_dp(4, star) == []
    assert hamiltonian_path_dp(4, [(0, 1), (2, 3)]) == []
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert _ok(4, k4, hamiltonian_path_dp(4, k4))
    assert hamiltonian_path_dp(0, []) == []
    assert stdlib_only()
    print('ham-06.v1 OK')
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
