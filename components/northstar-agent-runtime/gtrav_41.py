"""Topological sort with an explicit cycle report. IS: returns (order_or_None, has_cycle). IS NOT: silent None on cycles; the flag is always reported."""

from __future__ import annotations

import ast

VERSION = "gtrav-41.v1"

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

def dfs_toposort_report(graph: object) -> tuple:
    """Return (order or None, has_cycle bool)."""
    graph = _req_graph(graph)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict = {}
    order: list = []
    cyclic = [False]

    def visit(node: object) -> None:
        color[node] = GRAY
        for nxt in graph.get(node, []):
            c = color.get(nxt, WHITE)
            if c == GRAY:
                cyclic[0] = True
                return
            if c == WHITE:
                visit(nxt)
                if cyclic[0]:
                    return
        color[node] = BLACK
        order.append(node)

    nodes: set = set(graph)
    for vs in graph.values():
        nodes.update(vs)
    for root in nodes:
        if color.get(root, WHITE) == WHITE:
            visit(root)
            if cyclic[0]:
                return (None, True)
    order.reverse()
    return (order, False)


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
    g = {"a": ["b"], "b": ["c"], "c": []}
    order, cyc = dfs_toposort_report(g)
    assert cyc is False and order is not None and order.index("a") < order.index("c")
    order2, cyc2 = dfs_toposort_report({"a": ["b"], "b": ["a"]})
    assert cyc2 is True and order2 is None
    o3, c3 = dfs_toposort_report({})
    assert c3 is False and o3 == []
    try:
        dfs_toposort_report({"a": [2.5]})
    except ValueError:
        pass
    else:
        raise AssertionError("float neighbor must raise ValueError")
    assert stdlib_only()
    print("gtrav_41 OK")


if __name__ == "__main__":
    main()
