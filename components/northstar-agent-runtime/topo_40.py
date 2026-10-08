"""Topological sort variant: Kahn with seeded random tie-break (T-40)."""
from __future__ import annotations
import ast
import random
VERSION = "topo_40.v1"

import random

def topo_sort(graph, seed=0):
    rng = random.Random(seed)
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    zero = [u for u, d in indeg.items() if d == 0]
    order = []
    while zero:
        u = rng.choice(zero)
        zero.remove(u)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                zero.append(v)
    return order if len(order) == len(indeg) else None

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "random"}
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
    g = {"a": ["c"], "b": ["c"], "c": []}
    assert topo_sort(g, seed=1) == topo_sort(g, seed=1)
    o = topo_sort(g, seed=7)
    assert set(o) == {"a", "b", "c"} and o[-1] == "c"
    assert topo_sort({"a": ["b"], "b": ["a"]}, seed=3) is None
    assert stdlib_only()
    print("topo_40 OK")


if __name__ == "__main__":
    main()
