"""Kruskal early-stop with connectivity report (MST-007), Real."""
from __future__ import annotations
import ast

VERSION = "mst-07.v1"

def kruskal_early(n, edges):
    parent = list(range(n))
    rank = [0] * n
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    examined = 0
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        examined += 1
        ra, rb = find(u), find(v)
        if ra == rb:
            continue
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1
        mst.append((u, v, w))
        if len(mst) == n - 1:
            break
    connected = (n <= 1) or len(mst) == n - 1
    return sum(x[2] for x in mst), mst, connected, examined

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
    t, m, c, e = kruskal_early(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and c is True and e == 2
    t, m, c, e = kruskal_early(4, [(0, 1, 5), (2, 3, 7)])
    assert c is False and t == 12
    t, m, c, e = kruskal_early(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3 and c is True and e == 3
    assert stdlib_only()
    print("mst-07 OK")


if __name__ == "__main__":
    main()
