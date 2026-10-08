"""Topological sort variant: DFS returning cycle path on failure (T-05)."""
from __future__ import annotations
import ast

VERSION = "topo_05.v1"

def topo_sort(graph):
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {}
    for u in graph:
        color.setdefault(u, WHITE)
        for v in graph[u]:
            color.setdefault(v, WHITE)
    order = []
    cycle = []
    stack = []
    def visit(u):
        color[u] = GRAY
        stack.append(u)
        for v in graph.get(u, []):
            if color[v] == GRAY:
                i = stack.index(v)
                cycle.extend(stack[i:] + [v])
                return True
            if color[v] == WHITE and visit(v):
                return True
        stack.pop()
        color[u] = BLACK
        order.append(u)
        return False
    for u in list(color):
        if color[u] == WHITE:
            if visit(u):
                return None, cycle
    return order[::-1], []

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
    o, c = topo_sort({"a": ["b"], "b": ["c"], "c": []})
    assert c == [] and set(o) == {"a", "b", "c"}
    o2, c2 = topo_sort({"a": ["b"], "b": ["c"], "c": ["a"]})
    assert o2 is None and c2[0] == c2[-1] and set(c2) == {"a", "b", "c"}
    o3, c3 = topo_sort({"x": ["x"]})
    assert o3 is None and c3 == ["x", "x"]
    assert len(c2) == 4
    assert stdlib_only()
    print("topo_05 OK")


if __name__ == "__main__":
    main()
