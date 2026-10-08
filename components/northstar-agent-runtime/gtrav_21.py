"""Bipartite check via DFS 2-coloring. IS: recursive coloring returning True iff bipartite. IS NOT: the BFS variant; see gtrav_20."""

from __future__ import annotations

import ast

VERSION = "gtrav-21.v1"

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

def _undirected(graph: dict) -> dict:
    u: dict = {k: list(v) for k, v in graph.items()}
    for k, vs in graph.items():
        for n in vs:
            u.setdefault(n, [])
            if k not in u[n]:
                u[n].append(k)
    return u


def dfs_bipartite(graph: object) -> bool:
    """Return True iff the graph is bipartite (DFS coloring)."""
    graph = _req_graph(graph)
    u = _undirected(graph)
    color: dict = {}

    def visit(node: object, c: int) -> bool:
        color[node] = c
        for nxt in u.get(node, []):
            if nxt not in color:
                if not visit(nxt, 1 - c):
                    return False
            elif color[nxt] == c:
                return False
        return True

    for root in u:
        if root not in color:
            if not visit(root, 0):
                return False
    return True


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
    assert dfs_bipartite({"a": ["b"], "b": ["c"], "c": ["d"], "d": []}) is True
    assert dfs_bipartite({"a": ["b"], "b": ["c"], "c": ["a"]}) is False
    assert dfs_bipartite({"x": []}) is True
    try:
        dfs_bipartite([1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    assert stdlib_only()
    print("gtrav_21 OK")


if __name__ == "__main__":
    main()
