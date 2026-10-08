"""Topological sort variant: Kahn on an induced subgraph (T-47)."""
from __future__ import annotations
import ast

VERSION = "topo_47.v1"

def topo_sort_sub(graph, subset):
    keep = set(subset)
    indeg = {u: 0 for u in keep}
    for u in keep:
        for v in graph.get(u, []):
            if v in keep:
                indeg[v] += 1
    queue = [u for u in keep if indeg[u] == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            if v in keep:
                indeg[v] -= 1
                if indeg[v] == 0:
                    queue.append(v)
    return order if len(order) == len(keep) else None

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
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    o = topo_sort_sub(g, ["b", "c", "d"])
    assert set(o) == {"b", "c", "d"} and o[-1] == "d"
    assert topo_sort_sub(g, ["a", "b"]) == ["a", "b"]
    assert topo_sort_sub({"a": ["b"], "b": ["a"]}, ["a", "b"]) is None
    assert stdlib_only()
    print("topo_47 OK")


if __name__ == "__main__":
    main()
