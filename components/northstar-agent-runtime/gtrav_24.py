"""Directed cycle detection via DFS colors. IS: True iff a directed cycle exists. IS NOT: undirected cycle detection; see gtrav_25."""

from __future__ import annotations

import ast

VERSION = "gtrav-24.v1"

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

def dfs_directed_cycle(graph: object) -> bool:
    """Return True iff the directed graph contains a cycle."""
    graph = _req_graph(graph)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict = {}

    def visit(node: object) -> bool:
        color[node] = GRAY
        for nxt in graph.get(node, []):
            c = color.get(nxt, WHITE)
            if c == GRAY:
                return True
            if c == WHITE and visit(nxt):
                return True
        color[node] = BLACK
        return False

    nodes: set = set(graph)
    for vs in graph.values():
        nodes.update(vs)
    return any(
        color.get(n, WHITE) == WHITE and visit(n) for n in nodes
    )


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
    assert dfs_directed_cycle({"a": ["b"], "b": ["c"], "c": ["a"]}) is True
    assert dfs_directed_cycle({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) is False
    assert dfs_directed_cycle({"a": ["a"]}) is True
    assert dfs_directed_cycle({}) is False
    try:
        dfs_directed_cycle({"a": [2.5]})
    except ValueError:
        pass
    else:
        raise AssertionError("float neighbor must raise ValueError")
    assert stdlib_only()
    print("gtrav_24 OK")


if __name__ == "__main__":
    main()
