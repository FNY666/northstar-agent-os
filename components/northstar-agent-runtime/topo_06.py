"""Topological sort variant: iterative DFS with explicit iterator stack (T-06)."""
from __future__ import annotations
import ast

VERSION = "topo_06.v1"

def topo_sort(graph):
    nodes = list(graph)
    for u in graph:
        for v in graph[u]:
            if v not in graph and v not in nodes:
                nodes.append(v)
    visited = set()
    order = []
    for s in nodes:
        if s in visited:
            continue
        stack = [(s, iter(graph.get(s, [])))]
        on_path = {s}
        visited.add(s)
        while stack:
            u, it = stack[-1]
            advanced = False
            for v in it:
                if v in on_path:
                    return None
                if v not in visited:
                    visited.add(v)
                    on_path.add(v)
                    stack.append((v, iter(graph.get(v, []))))
                    advanced = True
                    break
            if not advanced:
                stack.pop()
                on_path.discard(u)
                order.append(u)
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
    assert topo_sort({}) == []
    assert stdlib_only()
    print("topo_06 OK")


if __name__ == "__main__":
    main()
