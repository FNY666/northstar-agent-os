"""Topological sort variant: Kahn on implicit graph via neighbor function (T-21)."""
from __future__ import annotations
import ast

VERSION = "topo_21.v1"

def topo_sort(nodes, neighbors):
    indeg = {u: 0 for u in nodes}
    for u in nodes:
        for v in neighbors(u):
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in neighbors(u):
            if v in indeg:
                indeg[v] -= 1
                if indeg[v] == 0:
                    queue.append(v)
    return order if len(order) == len(indeg) else None

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    nb = {1: [2], 2: [3], 3: []}
    assert topo_sort([1, 2, 3], lambda u: nb[u]) == [1, 2, 3]
    assert topo_sort([1, 2], lambda u: {1: [2], 2: [1]}[u]) is None
    assert topo_sort([], lambda u: []) == []
    assert topo_sort([5], lambda u: []) == [5]
    assert stdlib_only()
    print("topo_21 OK")


if __name__ == "__main__":
    main()
