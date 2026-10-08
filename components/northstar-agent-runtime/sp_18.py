"""Floyd-Warshall negative cycle detection (SP-018), Real."""
from __future__ import annotations
import ast

VERSION = "sp-18.v1"

INF = float("inf")

def floyd_warshall_nc(n, mat):
    d = [row[:] for row in mat]
    for k in range(n):
        for i in range(n):
            for j in range(n):
                if d[i][k] + d[k][j] < d[i][j]:
                    d[i][j] = d[i][k] + d[k][j]
    neg = [i for i in range(n) if d[i][i] < 0]
    return d, neg

def main() -> None:
    m = [[0, 1, INF], [INF, 0, -1], [-1, INF, 0]]
    d, neg = floyd_warshall_nc(3, m)
    assert len(neg) == 3
    m2 = [[0, 4, INF], [INF, 0, 2], [INF, INF, 0]]
    d, neg = floyd_warshall_nc(3, m2)
    assert neg == [] and d[0][2] == 6
    m3 = [[0, -5], [INF, 0]]
    d, neg = floyd_warshall_nc(2, m3)
    assert neg == []
    m4 = [[0, 1], [-2, 0]]
    d, neg = floyd_warshall_nc(2, m4)
    assert len(neg) == 2
    assert stdlib_only()
    print("sp-18 OK")

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
