"""Transitive closure (Warshall boolean) (SP-020), Real."""
from __future__ import annotations
import ast

VERSION = "sp-20.v1"

def transitive_closure(n, adj):
    reach = [[False] * n for _ in range(n)]
    for u in range(n):
        reach[u][u] = True
        for v in adj[u]:
            reach[u][v] = True
    for k in range(n):
        rk = reach[k]
        for i in range(n):
            if reach[i][k]:
                ri = reach[i]
                for j in range(n):
                    if rk[j]:
                        ri[j] = True
    return reach

def main() -> None:
    adj = [[1, 2], [3], [3], []]
    r = transitive_closure(4, adj)
    assert r[0][3] is True and r[3][0] is False
    assert r[1][2] is False and r[0][0] is True
    adj2 = [[1], [2], [0]]
    r = transitive_closure(3, adj2)
    assert all(r[i][j] for i in range(3) for j in range(3))
    assert transitive_closure(1, [[]]) == [[True]]
    adj3 = [[], [], []]
    r = transitive_closure(3, adj3)
    assert r[0][1] is False and r[1][1] is True
    assert stdlib_only()
    print("sp-20 OK")

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
