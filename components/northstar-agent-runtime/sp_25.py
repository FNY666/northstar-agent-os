"""DAG shortest path with at most K edges (SP-025), Real."""
from __future__ import annotations
import ast

VERSION = "sp-25.v1"

def topo_order(n, adj):
    indeg = [0] * n
    for u in range(n):
        for v, _ in adj[u]:
            indeg[v] += 1
    stack = [u for u in range(n) if indeg[u] == 0]
    order = []
    while stack:
        u = stack.pop()
        order.append(u)
        for v, _ in adj[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                stack.append(v)
    return order

INF = float("inf")

def dag_k_edges(n, adj, src, k):
    order = topo_order(n, adj)
    dist = [INF] * n
    dist[src] = 0
    for _ in range(k):
        nd = dist[:]
        for u in order:
            if dist[u] == INF:
                continue
            for v, w in adj[u]:
                if dist[u] + w < nd[v]:
                    nd[v] = dist[u] + w
        dist = nd
    return dist

def main() -> None:
    adj = [[(1, 1), (2, 5)], [(2, 1)], []]
    assert dag_k_edges(3, adj, 0, 1) == [0, 1, 5]
    assert dag_k_edges(3, adj, 0, 2) == [0, 1, 2]
    assert dag_k_edges(3, adj, 0, 0) == [0, INF, INF]
    assert dag_k_edges(1, [[]], 0, 3) == [0]
    assert stdlib_only()
    print("sp-25 OK")

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
