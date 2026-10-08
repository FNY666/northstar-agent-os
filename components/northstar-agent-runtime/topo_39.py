"""Topological sort variant: iterative DFS with expansion markers (T-39)."""
from __future__ import annotations
import ast

VERSION = "topo_39.v1"

def topo_sort(graph):
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {u: WHITE for u in graph}
    for u in graph:
        for v in graph[u]:
            color.setdefault(v, WHITE)
    order = []
    for s in list(color):
        if color[s] != WHITE:
            continue
        stack = [(s, False)]
        while stack:
            u, done = stack.pop()
            if done:
                color[u] = BLACK
                order.append(u)
                continue
            if color[u] == GRAY:
                return None
            if color[u] == BLACK:
                continue
            color[u] = GRAY
            stack.append((u, True))
            for v in graph.get(u, []):
                if color[v] == GRAY:
                    return None
                if color[v] == WHITE:
                    stack.append((v, False))
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
    assert topo_sort({1: [2], 2: [3], 3: []}) == [1, 2, 3]
    o = topo_sort({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert o[0] == "a" and o[-1] == "d"
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    assert stdlib_only()
    print("topo_39 OK")


if __name__ == "__main__":
    main()
