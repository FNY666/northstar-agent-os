"""MST verification via cut property (MST-032), Real."""
from __future__ import annotations
import ast
from collections import deque
VERSION = "mst-32.v1"

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


def verify_cut_property(n, edges, tree_edges):
    # Cut property: every tree edge must be a minimum-weight edge crossing
    # the cut formed by removing it from the tree.
    adj = [[] for _ in range(n)]
    for u, v, w in tree_edges:
        adj[u].append((v, w))
        adj[v].append((u, w))
    for tu, tv, tw in tree_edges:
        seen = [False] * n
        dq = deque([tu])
        seen[tu] = True
        while dq:
            u = dq.popleft()
            for v, _ in adj[u]:
                if (u == tu and v == tv) or (u == tv and v == tu):
                    continue
                if not seen[v]:
                    seen[v] = True
                    dq.append(v)
        best = None
        for u, v, w in edges:
            if u == v:
                continue
            if seen[u] != seen[v]:
                if best is None or w < best:
                    best = w
        if best is None or tw > best:
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
    assert verify_cut_property(3, e, _kruskal(3, e)) is True
    assert verify_cut_property(3, e, [(0, 1, 1), (0, 2, 3)]) is False
    e2 = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)]
    assert verify_cut_property(4, e2, _kruskal(4, e2)) is True
    assert stdlib_only()
    print("mst-32 OK")


if __name__ == "__main__":
    main()
