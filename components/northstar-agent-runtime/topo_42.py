"""Topological sort variant: generator-based DFS (T-42)."""
from __future__ import annotations
import ast

VERSION = "topo_42.v1"

def topo_gen(graph):
    visited = set()
    on_path = set()
    def visit(u):
        if u in on_path:
            raise ValueError("cycle at %r" % (u,))
        if u in visited:
            return
        on_path.add(u)
        for v in graph.get(u, []):
            yield from visit(v)
        on_path.discard(u)
        visited.add(u)
        yield u
    for u in graph:
        yield from visit(u)

def topo_sort(graph):
    try:
        return list(topo_gen(graph))[::-1]
    except ValueError:
        return None

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
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    assert list(topo_gen({"a": ["b"], "b": []})) == ["b", "a"]
    assert topo_sort({}) == []
    assert stdlib_only()
    print("topo_42 OK")


if __name__ == "__main__":
    main()
