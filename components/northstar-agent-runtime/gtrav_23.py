"""Topological sort via DFS post-order. IS: linear order of a DAG, None when a cycle exists. IS NOT: Kahn's algorithm; see gtrav_22."""

from __future__ import annotations

import ast

VERSION = "gtrav-23.v1"

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

def dfs_toposort(graph: object) -> object:
    """Return a topological order, or None if the graph has a cycle."""
    graph = _req_graph(graph)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict = {}
    order: list = []
    has_cycle = [False]

    def visit(node: object) -> None:
        color[node] = GRAY
        for nxt in graph.get(node, []):
            c = color.get(nxt, WHITE)
            if c == GRAY:
                has_cycle[0] = True
                return
            if c == WHITE:
                visit(nxt)
                if has_cycle[0]:
                    return
        color[node] = BLACK
        order.append(node)

    nodes: set = set(graph)
    for vs in graph.values():
        nodes.update(vs)
    for root in nodes:
        if color.get(root, WHITE) == WHITE:
            visit(root)
            if has_cycle[0]:
                return None
    order.reverse()
    return order


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
    order = dfs_toposort(g)
    assert order is not None
    pos = {n: i for i, n in enumerate(order)}
    assert pos["a"] < pos["b"] < pos["d"] and pos["a"] < pos["c"] < pos["d"]
    assert dfs_toposort({"a": ["b"], "b": ["a"]}) is None
    assert dfs_toposort({"a": ["a"]}) is None
    try:
        dfs_toposort(42)
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    assert stdlib_only()
    print("gtrav_23 OK")


if __name__ == "__main__":
    main()
