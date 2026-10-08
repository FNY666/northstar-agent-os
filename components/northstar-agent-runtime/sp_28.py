"""BFS with path reconstruction (SP-028), Real."""
from __future__ import annotations
import ast

VERSION = "sp-28.v1"

from collections import deque

def bfs_path(n, adj, src, dst):
    parent = [-1] * n
    dist = [-1] * n
    dist[src] = 0
    q = deque([src])
    while q:
        u = q.popleft()
        if u == dst:
            break
        for v in adj[u]:
            if dist[v] == -1:
                dist[v] = dist[u] + 1
                parent[v] = u
                q.append(v)
    if dist[dst] == -1:
        return -1, []
    path = []
    cur = dst
    while cur != -1:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return dist[dst], path

def main() -> None:
    line = [[1], [0, 2], [1, 3], [2]]
    d, p = bfs_path(4, line, 0, 3)
    assert d == 3 and p == [0, 1, 2, 3]
    d, p = bfs_path(4, line, 2, 2)
    assert d == 0 and p == [2]
    d, p = bfs_path(3, [[1], [], []], 0, 2)
    assert d == -1 and p == []
    d, p = bfs_path(4, [[1, 2], [3], [3], []], 0, 3)
    assert d == 2 and p[0] == 0 and p[-1] == 3 and len(p) == 3
    assert stdlib_only()
    print("sp-28 OK")

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
