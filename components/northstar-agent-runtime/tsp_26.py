"""Chinese postman: shortest closed walk covering every edge, exact via
minimum-weight matching on odd-degree vertices (TSP-026), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-chinese-postman.v1"


def chinese_postman(n, edges):
    """Exact on small graphs: sum(edges) + min-weight perfect matching over
    odd-degree vertices using shortest-path distances. edges: (u, v, w)."""
    if n == 0:
        return 0.0
    total = sum(w for _, _, w in edges)
    deg = [0] * n
    INF = math.inf
    d = [[INF] * n for _ in range(n)]
    for i in range(n):
        d[i][i] = 0.0
    for u, v, w in edges:
        deg[u] += 1
        deg[v] += 1
        if w < d[u][v]:
            d[u][v] = d[v][u] = w
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
    odd = [i for i in range(n) if deg[i] % 2 == 1]
    m = len(odd)
    # DP over subsets: minimum-weight perfect matching on odd vertices
    dp = [INF] * (1 << m)
    dp[0] = 0.0
    full = (1 << m) - 1
    for mask in range(full):
        if dp[mask] == INF:
            continue
        i = next(k for k in range(m) if not (mask >> k) & 1)
        for j in range(i + 1, m):
            if (mask >> j) & 1:
                continue
            nm = mask | (1 << i) | (1 << j)
            nd = dp[mask] + d[odd[i]][odd[j]]
            if nd < dp[nm]:
                dp[nm] = nd
    return total + dp[(1 << m) - 1]


def main() -> None:
    # small instance: triangle is Eulerian -> cost is exactly the edge sum
    tri = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0)]
    assert chinese_postman(3, tri) == 3.0
    # degenerate cases: no vertices, no edges
    assert chinese_postman(0, []) == 0.0
    assert chinese_postman(3, []) == 0.0
    # correctness property: path graph 0-1-2 needs the 0-2 shortest path
    # duplicated: (2+3) + d(0,2)=5 -> 10.0
    path2 = [(0, 1, 2.0), (1, 2, 3.0)]
    assert chinese_postman(3, path2) == 10.0
    # cost is never below the edge sum
    assert chinese_postman(4, [(0, 1, 5.0), (2, 3, 7.0)]) >= 12.0
    assert stdlib_only()
    print('tsp-chinese-postman.v1 OK')


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
