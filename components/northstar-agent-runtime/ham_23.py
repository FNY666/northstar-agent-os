"""Longest simple path via bitmask DP (HAM-023), Real."""
from __future__ import annotations
import ast

VERSION = "ham-23.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def longest_path_dp(n, edges):
    if n == 0:
        return 0
    adj = _adj(n, edges)
    N = 1 << n
    dp = [[-1] * n for _ in range(N)]
    for v in range(n):
        dp[1 << v][v] = 1
    for mask in range(N):
        for u in range(n):
            if dp[mask][u] < 0:
                continue
            for v in adj[u]:
                if not (mask >> v) & 1:
                    nm = mask | (1 << v)
                    if dp[nm][v] < dp[mask][u] + 1:
                        dp[nm][v] = dp[mask][u] + 1
    return max(max(row) for row in dp)

def main() -> None:
    assert longest_path_dp(4, [(0, 1), (1, 2), (2, 3)]) == 4
    assert longest_path_dp(3, [(0, 1), (1, 2), (0, 2)]) == 3
    assert longest_path_dp(4, [(0, 1), (0, 2), (0, 3)]) == 3
    assert longest_path_dp(3, []) == 1
    assert longest_path_dp(0, []) == 0
    assert stdlib_only()
    print('ham-23.v1 OK')
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
