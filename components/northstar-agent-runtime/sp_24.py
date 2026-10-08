"""DAG counting number of shortest paths (SP-024), Real."""
from __future__ import annotations
import ast

VERSION = "sp-24.v1"

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

def dag_count(n, adj, src):
    order = topo_order(n, adj)
    dist = [INF] * n
    cnt = [0] * n
    dist[src] = 0
    cnt[src] = 1
    pos = {u: i for i, u in enumerate(order)}
    for u in order[pos[src]:]:
        for v, w in adj[u]:
            nd = dist[u] + w
            if nd < dist[v]:
                dist[v] = nd
                cnt[v] = cnt[u]
            elif nd == dist[v]:
                cnt[v] += cnt[u]
    return dist, cnt

def main() -> None:
    adj = [[(1, 1), (2, 1)], [(3, 1)], [(3, 1)], []]
    d, c = dag_count(4, adj, 0)
    assert d[3] == 2 and c[3] == 2
    adj2 = [[(1, 2), (2, 1)], [(3, 1)], [(3, 2)], []]
    d, c = dag_count(4, adj2, 0)
    assert d[3] == 3 and c[3] == 2
    d, c = dag_count(3, [[(1, 1)], [], []], 0)
    assert d[2] == INF and c[2] == 0
    d, c = dag_count(1, [[]], 0)
    assert d == [0] and c == [1]
    assert stdlib_only()
    print("sp-24 OK")

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
