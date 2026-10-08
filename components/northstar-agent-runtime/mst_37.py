"""MST shape check (n-1 edges, acyclic, spanning) (MST-037), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-37.v1"

def check_mst_shape(n, tree_edges):
    if n == 0:
        return len(tree_edges) == 0
    if len(tree_edges) != n - 1:
        return False
    adj = [[] for _ in range(n)]
    for u, v, w in tree_edges:
        if u == v:
            return False
        adj[u].append(v)
        adj[v].append(u)
    seen = [False] * n
    seen[0] = True
    dq = deque([0])
    cnt = 1
    while dq:
        u = dq.popleft()
        for v in adj[u]:
            if not seen[v]:
                seen[v] = True
                cnt += 1
                dq.append(v)
    return cnt == n

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
    assert check_mst_shape(3, [(0, 1, 1), (1, 2, 2)]) is True
    assert check_mst_shape(3, [(0, 1, 1)]) is False
    assert check_mst_shape(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) is False
    assert check_mst_shape(4, [(0, 1, 1), (2, 3, 1)]) is False
    assert check_mst_shape(1, []) is True
    assert stdlib_only()
    print("mst-37 OK")


if __name__ == "__main__":
    main()
