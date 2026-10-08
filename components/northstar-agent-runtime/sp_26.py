"""BFS unweighted shortest path (SP-026), Real."""
from __future__ import annotations
import ast

VERSION = "sp-26.v1"

from collections import deque
INF = float("inf")

def bfs(n, adj, src):
    dist = [-1] * n
    dist[src] = 0
    q = deque([src])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if dist[v] == -1:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist

def main() -> None:
    assert bfs(4, [[1], [0, 2], [1, 3], [2]], 0) == [0, 1, 2, 3]
    assert bfs(3, [[1], [], []], 0) == [0, 1, -1]
    assert bfs(1, [[]], 0) == [0]
    star = [[1, 2, 3], [0], [0], [0]]
    assert bfs(4, star, 0) == [0, 1, 1, 1]
    assert stdlib_only()
    print("sp-26 OK")

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
