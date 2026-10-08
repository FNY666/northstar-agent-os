"""Floyd-Warshall with path reconstruction (SP-017), Real."""
from __future__ import annotations
import ast

VERSION = "sp-17.v1"

INF = float("inf")

def floyd_warshall_path(n, mat):
    d = [row[:] for row in mat]
    nxt = [[None] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i != j and mat[i][j] < INF:
                nxt[i][j] = j
    for k in range(n):
        for i in range(n):
            for j in range(n):
                if d[i][k] + d[k][j] < d[i][j]:
                    d[i][j] = d[i][k] + d[k][j]
                    nxt[i][j] = nxt[i][k]
    def path(i, j):
        if nxt[i][j] is None:
            return []
        p = [i]
        while i != j:
            i = nxt[i][j]
            p.append(i)
        return p
    return d, path

def main() -> None:
    m = [[0, 4, INF], [INF, 0, 2], [INF, INF, 0]]
    d, path = floyd_warshall_path(3, m)
    assert d[0][2] == 6 and path(0, 2) == [0, 1, 2]
    assert path(0, 0) == [] and path(2, 0) == []
    assert path(1, 2) == [1, 2]
    m2 = [[0, 1, INF, INF], [INF, 0, 1, INF], [INF, INF, 0, 1], [INF, INF, INF, 0]]
    d, path = floyd_warshall_path(4, m2)
    assert d[0][3] == 3 and path(0, 3) == [0, 1, 2, 3]
    assert stdlib_only()
    print("sp-17 OK")

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
