"""Reverse-delete forest (disconnected graphs) (MST-030), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-30.v1"

def reverse_delete_forest(n, edges):
    ed = sorted([(u, v, w) for u, v, w in edges if u != v], key=lambda e: -e[2])
    keep = [True] * len(ed)
    def components(exclude_idx):
        adj = [[] for _ in range(n)]
        for i, (u, v, w) in enumerate(ed):
            if i == exclude_idx or not keep[i]:
                continue
            adj[u].append(v)
            adj[v].append(u)
        seen = [False] * n
        count = 0
        for s in range(n):
            if not seen[s]:
                count += 1
                seen[s] = True
                dq = deque([s])
                while dq:
                    u = dq.popleft()
                    for v in adj[u]:
                        if not seen[v]:
                            seen[v] = True
                            dq.append(v)
        return count
    base = components(-1)
    for i in range(len(ed)):
        if components(i) == base:
            keep[i] = False
    forest = [e for e, k in zip(ed, keep) if k]
    return sum(w for _, _, w in forest), forest

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
    t, f = reverse_delete_forest(4, [(0, 1, 5), (2, 3, 7)])
    assert t == 12 and len(f) == 2
    t, f = reverse_delete_forest(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(f) == 2
    t, f = reverse_delete_forest(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 9)])
    assert t == 3
    assert stdlib_only()
    print("mst-30 OK")


if __name__ == "__main__":
    main()
