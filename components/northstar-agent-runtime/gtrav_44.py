"""BFS with a node predicate filter. IS: traverses only nodes where pred(node) is True. IS NOT: post-filtering a full traversal."""

from __future__ import annotations

import ast

VERSION = "gtrav-44.v1"

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

def bfs_filtered(graph: object, start: object, pred: object) -> list:
    """Return BFS order restricted to nodes satisfying pred."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if not callable(pred):
        raise ValueError("pred must be callable")
    if not pred(start):
        return []
    order: list = []
    seen: set = {start}
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nxt in graph.get(node, []):
            if nxt not in seen and pred(nxt):
                seen.add(nxt)
                queue.append(nxt)
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
    assert bfs_filtered(g, "a", lambda n: n != "c") == ["a", "b", "d"]
    assert bfs_filtered(g, "a", lambda n: True) == ["a", "b", "c", "d"]
    assert bfs_filtered(g, "a", lambda n: False) == []
    try:
        bfs_filtered(g, "a", "not-callable")
    except ValueError:
        pass
    else:
        raise AssertionError("non-callable pred must raise ValueError")
    try:
        bfs_filtered(g, "zzz", lambda n: True)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_44 OK")


if __name__ == "__main__":
    main()
