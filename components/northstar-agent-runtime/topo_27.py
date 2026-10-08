"""Topological sort variant: Kahn type-checked for int nodes (T-27)."""
from __future__ import annotations
import ast

VERSION = "topo_27.v1"

def topo_sort(graph):
    for u in graph:
        if not isinstance(u, int) or isinstance(u, bool):
            raise TypeError("node %r is not int" % (u,))
        for v in graph[u]:
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError("node %r is not int" % (v,))
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
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
    assert topo_sort({1: [2], 2: [3], 3: []}) == [1, 2, 3]
    try:
        topo_sort({"a": ["b"]})
        raise AssertionError("expected TypeError")
    except TypeError:
        pass
    assert topo_sort({1: [2], 2: [1]}) is None
    assert stdlib_only()
    print("topo_27 OK")


if __name__ == "__main__":
    main()
