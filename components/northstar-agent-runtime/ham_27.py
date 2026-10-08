"""DAG Hamiltonian path via topological order (HAM-027), Real."""
from __future__ import annotations
import ast

VERSION = "ham-27.v1"

def _dok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set(edges)
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def dag_ham_path(n, edges):
    from collections import deque
    indeg = [0] * n
    adj = [[] for _ in range(n)]
    for u, v in edges:
        adj[u].append(v)
        indeg[v] += 1
    q = deque([i for i in range(n) if indeg[i] == 0])
    topo = []
    while q:
        u = q.popleft()
        topo.append(u)
        for v in adj[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(topo) != n:
        return []
    eset = set(edges)
    if all((topo[i], topo[i + 1]) in eset for i in range(n - 1)):
        return topo
    return []

def main() -> None:
    e = [(0, 1), (1, 2), (2, 3), (0, 2)]
    assert _dok(4, e, dag_ham_path(4, e))
    diamond = [(0, 1), (0, 2), (1, 3), (2, 3)]
    assert dag_ham_path(4, diamond) == []
    assert dag_ham_path(3, [(0, 1), (1, 2), (2, 0)]) == []
    assert dag_ham_path(0, []) == []
    assert _dok(1, [], dag_ham_path(1, []))
    assert stdlib_only()
    print('ham-27.v1 OK')
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
