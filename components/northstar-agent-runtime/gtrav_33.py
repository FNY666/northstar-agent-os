"""BFS visiting neighbors in lexicographic order. IS: deterministic BFS with sorted adjacency. IS NOT: adjacency-order BFS; see gtrav_04."""

from __future__ import annotations

import ast

VERSION = "gtrav-33.v1"

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

def bfs_lexicographic(graph: object, start: object) -> list:
    """Return BFS order with neighbors sorted by str()."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    seen: set = {start}
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nxt in sorted(graph.get(node, []), key=str):
            if nxt not in seen:
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
    g = {"a": ["c", "b"], "b": ["d"], "c": ["d"], "d": []}
    assert bfs_lexicographic(g, "a") == ["a", "b", "c", "d"]
    assert bfs_lexicographic({"x": []}, "x") == ["x"]
    assert bfs_lexicographic({"a": ["b"], "b": [], "z": []}, "a") == ["a", "b"]
    try:
        bfs_lexicographic(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_33 OK")


if __name__ == "__main__":
    main()
