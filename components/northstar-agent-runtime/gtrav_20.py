"""Bipartite check via BFS 2-coloring. IS: True iff the undirected view is 2-colorable. IS NOT: a coloring output; see gtrav_21 for DFS coloring."""

from __future__ import annotations

import ast

VERSION = "gtrav-20.v1"

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


def bfs_bipartite(graph: object) -> bool:
    """Return True iff the graph is bipartite."""
    graph = _req_graph(graph)
    u = _undirected(graph)
    color: dict = {}
    for root in u:
        if root in color:
            continue
        color[root] = 0
        queue: list = [root]
        while queue:
            node = queue.pop(0)
            for nxt in u.get(node, []):
                if nxt not in color:
                    color[nxt] = 1 - color[node]
                    queue.append(nxt)
                elif color[nxt] == color[node]:
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
    assert bfs_bipartite({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) is True
    assert bfs_bipartite({"a": ["b"], "b": ["c"], "c": ["a"]}) is False
    assert bfs_bipartite({"x": []}) is True
    assert bfs_bipartite({}) is True
    try:
        bfs_bipartite({"a": [3.5]})
    except ValueError:
        pass
    else:
        raise AssertionError("float neighbor must raise ValueError")
    assert stdlib_only()
    print("gtrav_20 OK")


if __name__ == "__main__":
    main()
