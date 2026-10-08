"""Floyd-Warshall basic (SP-016), Real."""
from __future__ import annotations
import ast

VERSION = "sp-16.v1"

INF = float("inf")

def floyd_warshall(n, mat):
    d = [row[:] for row in mat]
    for k in range(n):
        dk = d[k]
        for i in range(n):
            dik = d[i][k]
            if dik == INF:
                continue
            di = d[i]
            for j in range(n):
                nd = dik + dk[j]
                if nd < di[j]:
                    di[j] = nd
    return d

def main() -> None:
    m = [[0, 4, INF, INF], [INF, 0, 2, 5], [INF, INF, 0, 1], [INF, INF, INF, 0]]
    d = floyd_warshall(4, m)
    assert d[0] == [0, 4, 6, 7] and d[0][3] == 7
    assert d[3][0] == INF
    assert floyd_warshall(1, [[0]]) == [[0]]
    m2 = [[0, 1], [INF, 0]]
    assert floyd_warshall(2, m2) == [[0, 1], [INF, 0]]
    assert stdlib_only()
    print("sp-16 OK")

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
