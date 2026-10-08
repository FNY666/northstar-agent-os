"""MST verification via cycle property (MST-031), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-31.v1"

def _kruskal(n, edges):
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
    return mst


def verify_cycle_property(n, edges, tree_edges):
    # Cycle property: every non-tree edge must weigh >= the maximum edge
    # weight on the tree path between its endpoints.
    adj = [[] for _ in range(n)]
    for u, v, w in tree_edges:
        adj[u].append((v, w))
        adj[v].append((u, w))
    tree_set = {(min(u, v), max(u, v), w) for u, v, w in tree_edges}
    def max_on_path(s, t):
        prev = [-1] * n
        pw = [0] * n
        prev[s] = s
        dq = deque([s])
        while dq:
            u = dq.popleft()
            if u == t:
                break
            for v, w in adj[u]:
                if prev[v] == -1:
                    prev[v] = u
                    pw[v] = w
                    dq.append(v)
        if prev[t] == -1:
            return None
        mx = 0
        cur = t
        while cur != s:
            mx = max(mx, pw[cur])
            cur = prev[cur]
        return mx
    for u, v, w in edges:
        if u == v:
            continue
        if (min(u, v), max(u, v), w) in tree_set:
            continue
        mx = max_on_path(u, v)
        if mx is None or w < mx:
            return False
    return True

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
    e = [(0, 1, 1), (1, 2, 2), (0, 2, 3)]
    assert verify_cycle_property(3, e, _kruskal(3, e)) is True
    assert verify_cycle_property(3, e, [(0, 1, 1), (0, 2, 3)]) is False
    e2 = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)]
    assert verify_cycle_property(4, e2, _kruskal(4, e2)) is True
    assert stdlib_only()
    print("mst-31 OK")


if __name__ == "__main__":
    main()
