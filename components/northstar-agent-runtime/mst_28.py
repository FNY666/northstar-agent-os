"""Reverse-delete DFS connectivity (MST-028), Real."""
from __future__ import annotations
import ast

VERSION = "mst-28.v1"

def reverse_delete_dfs(n, edges):
    ed = sorted([(u, v, w) for u, v, w in edges if u != v], key=lambda e: -e[2])
    keep = [True] * len(ed)
    def connected(exclude_idx):
        adj = [[] for _ in range(n)]
        for i, (u, v, w) in enumerate(ed):
            if i == exclude_idx or not keep[i]:
                continue
            adj[u].append(v)
            adj[v].append(u)
        seen = [False] * n
        stack = [0]
        seen[0] = True
        while stack:
            u = stack.pop()
            for v in adj[u]:
                if not seen[v]:
                    seen[v] = True
                    stack.append(v)
        return all(seen)
    for i in range(len(ed)):
        if connected(i):
            keep[i] = False
    mst = [e for e, k in zip(ed, keep) if k]
    return sum(w for _, _, w in mst), mst

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    t, m = reverse_delete_dfs(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = reverse_delete_dfs(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    assert stdlib_only()
    print("mst-28 OK")


if __name__ == "__main__":
    main()
