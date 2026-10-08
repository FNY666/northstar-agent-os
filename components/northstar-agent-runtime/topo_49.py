"""Topological sort variant: DFS returning an immutable tuple (T-49)."""
from __future__ import annotations
import ast

VERSION = "topo_49.v1"

def topo_sort(graph):
    visited = set()
    on_path = set()
    order = []
    bad = []
    def visit(u):
        if bad or u in visited:
            return
        if u in on_path:
            bad.append(True)
            return
        on_path.add(u)
        for v in graph.get(u, []):
            visit(v)
        on_path.discard(u)
        visited.add(u)
        order.append(u)
    for u in graph:
        visit(u)
    if bad:
        return None
    return tuple(order[::-1])

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
    o = topo_sort({1: [2], 2: [3], 3: []})
    assert isinstance(o, tuple) and o == (1, 2, 3)
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    assert topo_sort({}) == ()
    assert stdlib_only()
    print("topo_49 OK")


if __name__ == "__main__":
    main()
