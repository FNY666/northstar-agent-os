"""DFS returning visit order plus parent map. IS: (order, parent) where parent[start] is None. IS NOT: BFS parents; see gtrav_35."""

from __future__ import annotations

import ast

VERSION = "gtrav-34.v1"

def _req_graph(graph: object) -> dict:
    """Fail-closed: graph must be a dict of node -> list of neighbor nodes."""
    if not isinstance(graph, dict):
        raise ValueError("graph must be a dict")
    for key, val in graph.items():
        if not isinstance(key, (str, int)):
            raise ValueError("node keys must be str or int")
        if not isinstance(val, list):
            raise ValueError("adjacency value must be a list")
        for nxt in val:
            if not isinstance(nxt, (str, int)):
                raise ValueError("neighbors must be str or int")
    return graph


def _req_start(graph: dict, start: object) -> None:
    if start not in graph:
        raise ValueError("start must be a node in graph")

def dfs_with_parents(graph: object, start: object) -> tuple:
    """Return (order, parent) from iterative DFS."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    parent: dict = {start: None}
    seen: set = set()
    stack: list = [start]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        order.append(node)
        for nxt in reversed(graph.get(node, [])):
            if nxt not in seen and nxt not in parent:
                parent[nxt] = node
                stack.append(nxt)
    return (order, parent)


def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    order, parent = dfs_with_parents(g, "a")
    assert order == ["a", "b", "d", "c"]
    assert parent == {"a": None, "b": "a", "c": "a", "d": "b"}
    o2, p2 = dfs_with_parents({"x": []}, "x")
    assert o2 == ["x"] and p2 == {"x": None}
    try:
        dfs_with_parents(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_34 OK")


if __name__ == "__main__":
    main()
