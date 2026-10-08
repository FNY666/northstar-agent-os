"""Critical edges (in every MST) (MST-035), Real."""
from __future__ import annotations
import ast

VERSION = "mst-35.v1"

def _mst_weight(n, edges, skip=-1):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0
    cnt = 0
    for i in sorted(range(len(edges)), key=lambda j: edges[j][2]):
        if i == skip:
            continue
        u, v, w = edges[i]
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            total += w
            cnt += 1
            if cnt == n - 1:
                break
    return total if cnt == n - 1 else None


def critical_edges(n, edges):
    # An edge is critical if removing it raises the MST weight or
    # disconnects the graph.
    base = _mst_weight(n, edges)
    if base is None:
        return []
    crit = []
    for i, e in enumerate(edges):
        if e[0] == e[1]:
            continue
        w2 = _mst_weight(n, edges, skip=i)
        if w2 is None or w2 > base:
            crit.append(e)
    return crit

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
    c = critical_edges(3, e)
    assert (0, 1, 1) in c and (1, 2, 2) in c and (0, 2, 3) not in c
    e2 = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)]
    assert critical_edges(4, e2) == []  # cycle: nothing critical
    e3 = [(0, 1, 5), (1, 2, 6)]
    assert len(critical_edges(3, e3)) == 2  # bridge edges
    assert stdlib_only()
    print("mst-35 OK")


if __name__ == "__main__":
    main()
