"""DAG longest path (critical path) (SP-022), Real."""
from __future__ import annotations
import ast

VERSION = "sp-22.v1"

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

NINF = float("-inf")

def dag_longest(n, adj, src):
    order = topo_order(n, adj)
    dist = [NINF] * n
    dist[src] = 0
    pos = {u: i for i, u in enumerate(order)}
    for u in order[pos[src]:]:
        for v, w in adj[u]:
            if dist[u] + w > dist[v]:
                dist[v] = dist[u] + w
    return dist

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(3, 5)], [(1, 2), (3, 1)], []]
    assert dag_longest(4, adj, 0) == [0, 4, 1, 9]
    assert dag_longest(3, [[(1, 1)], [], []], 0) == [0, 1, NINF]
    assert dag_longest(1, [[]], 0) == [0]
    proj = [[(1, 3), (2, 2)], [(3, 4)], [(3, 1)], []]
    assert dag_longest(4, proj, 0)[3] == 7
    assert stdlib_only()
    print("sp-22 OK")

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
