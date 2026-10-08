"""DAG shortest path with reconstruction (SP-023), Real."""
from __future__ import annotations
import ast

VERSION = "sp-23.v1"

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

def dag_shortest_path(n, adj, src, dst):
    order = topo_order(n, adj)
    dist = [INF] * n
    parent = [-1] * n
    dist[src] = 0
    pos = {u: i for i, u in enumerate(order)}
    for u in order[pos[src]:]:
        for v, w in adj[u]:
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                parent[v] = u
    if dist[dst] == INF:
        return INF, []
    path = []
    cur = dst
    while cur != -1:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return dist[dst], path

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(3, 5)], [(1, 2), (3, 1)], []]
    d, p = dag_shortest_path(4, adj, 0, 3)
    assert d == 2 and p == [0, 2, 3]
    d, p = dag_shortest_path(4, adj, 0, 0)
    assert d == 0 and p == [0]
    d, p = dag_shortest_path(4, [[(1, 1)], [], [], []], 0, 3)
    assert d == INF and p == []
    d, p = dag_shortest_path(3, [[(1, 1)], [(2, -2)], []], 0, 2)
    assert d == -1 and p == [0, 1, 2]
    assert stdlib_only()
    print("sp-23 OK")

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
