"""Topological sort variant: Kahn with priority tie-break function (T-34)."""
from __future__ import annotations
import ast
import heapq
import itertools
VERSION = "topo_34.v1"

import heapq
import itertools

def topo_sort(graph, priority):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    ctr = itertools.count()
    heap = [(priority(u), next(ctr), u) for u, d in indeg.items() if d == 0]
    heapq.heapify(heap)
    order = []
    while heap:
        _, _, u = heapq.heappop(heap)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                heapq.heappush(heap, (priority(v), next(ctr), v))
    return order if len(order) == len(indeg) else None

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "heapq", "itertools"}
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
    g = {"bb": ["d"], "a": ["d"], "ccc": [], "d": []}
    assert topo_sort(g, len)[0] == "a"
    assert topo_sort(g, lambda u: -len(u))[0] == "ccc"
    assert topo_sort({"a": ["b"], "b": ["a"]}, len) is None
    assert stdlib_only()
    print("topo_34 OK")


if __name__ == "__main__":
    main()
