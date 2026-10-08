"""Second-best MST via single edge swap (MST-039), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-39.v1"

def second_best_mst(n, edges):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            mst.append((u, v, w))
    if len(mst) != n - 1:
        return None
    total = sum(w for _, _, w in mst)
    adj = [[] for _ in range(n)]
    for u, v, w in mst:
        adj[u].append((v, w))
        adj[v].append((u, w))
    def max_on_path(s, t):
        prev = [-1] * n
        pw = [0] * n
        prev[s] = s
        dq = deque([s])
        while dq:
            u = dq.popleft()
            for v, w in adj[u]:
                if prev[v] == -1:
                    prev[v] = u
                    pw[v] = w
                    dq.append(v)
        mx = 0
        cur = t
        while cur != s:
            mx = max(mx, pw[cur])
            cur = prev[cur]
        return mx
    tree_keys = {(min(u, v), max(u, v), w) for u, v, w in mst}
    best2 = None
    for u, v, w in edges:
        if u == v:
            continue
        if (min(u, v), max(u, v), w) in tree_keys:
            continue
        cand = total - max_on_path(u, v) + w
        if cand > total and (best2 is None or cand < best2):
            best2 = cand
    return best2

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
    assert second_best_mst(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) == 4
    assert second_best_mst(3, [(0, 1, 2), (1, 2, 2), (0, 2, 2)]) is None  # all ties
    r = second_best_mst(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 5)])
    assert r == 7, r  # 3 - 1 + 5
    assert stdlib_only()
    print("mst-39 OK")


if __name__ == "__main__":
    main()
