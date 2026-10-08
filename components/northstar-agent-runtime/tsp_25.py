"""Rural postman: shortest closed walk traversing a required edge subset (TSP-025), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-rural-postman.v1"


def rural_postman(n, edges, required):
    """Mock rural postman: cost = sum(required edges) + 2 * (MST cost to
    connect the required-edge components via shortest paths). Doubling the
    connectors yields a feasible closed walk traversing every required edge.
    edges: list of (u, v, w); required: set of edge indices."""
    if n == 0:
        return 0.0
    INF = math.inf
    d = [[INF] * n for _ in range(n)]
    for i in range(n):
        d[i][i] = 0.0
    for u, v, w in edges:
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
    req_cost = sum(edges[i][2] for i in required)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    verts = set()
    for i in required:
        u, v, _ = edges[i]
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv
        verts.add(u)
        verts.add(v)
    comps = {}
    for x in verts:
        comps.setdefault(find(x), []).append(x)
    clist = list(comps.values())
    m = len(clist)
    conn = 0.0
    if m > 1:
        # Prim's MST over components with shortest-path distances
        in_tree = [False] * m
        key = [INF] * m
        key[0] = 0.0
        for _ in range(m):
            u = min((key[i], i) for i in range(m) if not in_tree[i])[1]
            in_tree[u] = True
            conn += key[u]
            for v in range(m):
                if not in_tree[v]:
                    c = min(d[x][y] for x in clist[u] for y in clist[v])
                    if c < key[v]:
                        key[v] = c
    return req_cost + 2.0 * conn


def main() -> None:
    # small instance: path edges required, all connected -> just the sum
    edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (0, 3, 10.0)]
    assert rural_postman(4, edges, {0, 1, 2}) == 3.0
    # degenerate cases: no vertices / no required edges
    assert rural_postman(0, [], set()) == 0.0
    assert rural_postman(4, edges, set()) == 0.0
    # correctness property: disconnected required components get connected
    # via shortest paths (doubled): comps {0,1},{2,3}, link cost d(1,2)=1
    assert rural_postman(4, edges, {0, 2}) == 2.0 + 2.0 * 1.0
    # cost is never below the required-edge sum
    assert rural_postman(4, edges, {0, 1, 3}) >= 12.0
    assert stdlib_only()
    print('tsp-rural-postman.v1 OK')


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
