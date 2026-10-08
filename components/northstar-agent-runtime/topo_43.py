"""Topological sort variant: Kahn with precomputed indegrees (T-43)."""
from __future__ import annotations
import ast

VERSION = "topo_43.v1"

def topo_sort(nodes, indeg, succ):
    indeg = dict(indeg)
    queue = [u for u in nodes if indeg.get(u, 0) == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in succ.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return order if len(order) == len(nodes) else None

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
    assert topo_sort(["a", "b", "c"], {"a": 0, "b": 1, "c": 1}, {"a": ["b", "c"]}) == ["a", "b", "c"]
    assert topo_sort(["a", "b"], {"a": 1, "b": 1}, {"a": ["b"], "b": ["a"]}) is None
    assert topo_sort([], {}, {}) == []
    assert stdlib_only()
    print("topo_43 OK")


if __name__ == "__main__":
    main()
