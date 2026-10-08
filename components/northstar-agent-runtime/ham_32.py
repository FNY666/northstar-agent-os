"""Self avoiding walk enumeration (HAM-032), Real."""
from __future__ import annotations
import ast

VERSION = "ham-32.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def self_avoiding_walks(n, edges, s, k):
    adj = _adj(n, edges)
    res = []
    def dfs(path, used):
        if len(path) == k + 1:
            res.append(list(path))
            return
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                dfs(path, used)
                path.pop()
                used.remove(v)
    dfs([s], {s})
    return res

def main() -> None:
    p3 = [(0, 1), (1, 2)]
    assert self_avoiding_walks(3, p3, 0, 2) == [[0, 1, 2]]
    assert self_avoiding_walks(3, p3, 0, 1) == [[0, 1]]
    tri = [(0, 1), (1, 2), (2, 0)]
    assert self_avoiding_walks(3, tri, 0, 2) == [[0, 1, 2], [0, 2, 1]]
    assert self_avoiding_walks(3, tri, 0, 0) == [[0]]
    assert self_avoiding_walks(3, [], 0, 1) == []
    assert stdlib_only()
    print('ham-32.v1 OK')
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
