"""Count DAG Hamiltonian paths via subset DP (HAM-028), Real."""
from __future__ import annotations
import ast

VERSION = "ham-28.v1"

def _dadj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
    return a

def count_dag_ham_paths(n, edges):
    adj = _dadj(n, edges)
    N = 1 << n
    dp = [[0] * n for _ in range(N)]
    for v in range(n):
        dp[1 << v][v] = 1
    for mask in range(N):
        for u in range(n):
            c = dp[mask][u]
            if c:
                for v in adj[u]:
                    if not (mask >> v) & 1:
                        dp[mask | (1 << v)][v] += c
    return sum(dp[N - 1])

def main() -> None:
    e = [(0, 1), (1, 2), (2, 3)]
    assert count_dag_ham_paths(4, e) == 1
    assert count_dag_ham_paths(3, []) == 0
    assert count_dag_ham_paths(1, []) == 1
    assert count_dag_ham_paths(0, []) == 0
    e2 = [(0, 1), (0, 2), (1, 2)]
    assert count_dag_ham_paths(3, e2) == 1
    assert stdlib_only()
    print('ham-28.v1 OK')
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
