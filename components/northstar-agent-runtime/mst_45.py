"""Dynamic MST single edge insertion update (MST-045), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-45.v1"

def mst_insert_edge(n, mst_edges, new_edge):
    # Dynamic MST: inserting one edge creates exactly one cycle; swap out
    # the maximum-weight edge on that cycle if the new edge is lighter.
    u0, v0, w0 = new_edge
    adj = [[] for _ in range(n)]
    for u, v, w in mst_edges:
        adj[u].append((v, w))
        adj[v].append((u, w))
    prev = [-1] * n
    pw = [0] * n
    pe = [None] * n
    prev[u0] = u0
    dq = deque([u0])
    while dq:
        u = dq.popleft()
        for v, w in adj[u]:
            if prev[v] == -1:
                prev[v] = u
                pw[v] = w
                pe[v] = (u, v, w)
                dq.append(v)
    if prev[v0] == -1:
        return mst_edges + [new_edge]
    mx = 0
    me = None
    cur = v0
    while cur != u0:
        if pw[cur] > mx:
            mx = pw[cur]
            me = pe[cur]
        cur = prev[cur]
    if w0 < mx:
        return [e for e in mst_edges if e != me] + [new_edge]
    return list(mst_edges)

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
    mst = [(0, 1, 1), (1, 2, 2)]
    r = mst_insert_edge(3, mst, (0, 2, 1))
    assert sum(w for _, _, w in r) == 2  # swapped out (1,2,2)
    r = mst_insert_edge(3, mst, (0, 2, 9))
    assert sum(w for _, _, w in r) == 3  # heavier, no swap
    r = mst_insert_edge(4, mst, (2, 3, 4))
    assert len(r) == 3  # connects new vertex
    assert stdlib_only()
    print("mst-45 OK")


if __name__ == "__main__":
    main()
