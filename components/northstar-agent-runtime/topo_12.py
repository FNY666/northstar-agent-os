"""Topological sort variant: DFS with white/gray/black coloring (T-12)."""
from __future__ import annotations
import ast

VERSION = "topo_12.v1"

def topo_sort(graph):
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {u: WHITE for u in graph}
    for u in graph:
        for v in graph[u]:
            if v not in color:
                color[v] = WHITE
    order = []
    bad = []
    def visit(u):
        color[u] = GRAY
        for v in graph.get(u, []):
            if color[v] == GRAY:
                bad.append(True)
                return
            if color[v] == WHITE:
                visit(v)
        color[u] = BLACK
        order.append(u)
    for u in list(color):
        if color[u] == WHITE and not bad:
            visit(u)
    if bad:
        return None
    return order[::-1]

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
    o = topo_sort({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert o[0] == "a" and o[-1] == "d"
    assert topo_sort({"a": ["b"], "b": ["c"], "c": ["a"]}) is None
    assert topo_sort({"a": ["a"]}) is None
    assert topo_sort({"z": []}) == ["z"]
    assert stdlib_only()
    print("topo_12 OK")


if __name__ == "__main__":
    main()
