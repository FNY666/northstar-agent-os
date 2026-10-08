"""Reverse-delete BFS connectivity (MST-027), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-27.v1"

def reverse_delete(n, edges):
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
        seen[0] = True
        dq = deque([0])
        while dq:
            u = dq.popleft()
            for v in adj[u]:
                if not seen[v]:
                    seen[v] = True
                    dq.append(v)
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
    t, m = reverse_delete(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = reverse_delete(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = reverse_delete(2, [(0, 1, 5)])
    assert t == 5 and len(m) == 1
    assert stdlib_only()
    print("mst-27 OK")


if __name__ == "__main__":
    main()
