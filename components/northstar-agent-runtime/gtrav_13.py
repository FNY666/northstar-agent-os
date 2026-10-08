"""BFS with early exit on target. IS: stops expanding once the target is dequeued. IS NOT: a full traversal; unvisited nodes are intentionally skipped."""

from __future__ import annotations

import ast

VERSION = "gtrav-13.v1"

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

def bfs_early_exit(graph: object, start: object, target: object) -> list:
    """Return BFS visit order, stopping right after the target is dequeued."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    order: list = []
    seen: set = {start}
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        order.append(node)
        if node == target:
            break
        for nxt in graph.get(node, []):
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
    g = {"a": ["b", "c"], "b": ["d"], "c": ["e"], "d": [], "e": []}
    assert bfs_early_exit(g, "a", "b") == ["a", "b"]
    assert bfs_early_exit(g, "a", "d") == ["a", "b", "c", "d"]
    assert bfs_early_exit(g, "a", "e") == ["a", "b", "c", "d", "e"]
    try:
        bfs_early_exit(g, "a", "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown target must raise ValueError")
    assert stdlib_only()
    print("gtrav_13 OK")


if __name__ == "__main__":
    main()
