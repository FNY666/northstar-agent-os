"""Depth-limited BFS. IS: visits only nodes within max_depth edges of start. IS NOT: unbounded BFS; deeper nodes are excluded."""

from __future__ import annotations

import ast

VERSION = "gtrav-50.v1"

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

def bfs_depth_limited(graph: object, start: object, max_depth: object) -> list:
    """Return BFS order limited to max_depth."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative int")
    order: list = []
    seen: set = {start}
    queue: list = [(start, 0)]
    while queue:
        node, depth = queue.pop(0)
        order.append(node)
        if depth == max_depth:
            continue
        for nxt in graph.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, depth + 1))
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
    assert bfs_depth_limited(g, "a", 0) == ["a"]
    assert bfs_depth_limited(g, "a", 1) == ["a", "b", "c"]
    assert bfs_depth_limited(g, "a", 2) == ["a", "b", "c", "d"]
    assert bfs_depth_limited(g, "a", 99) == ["a", "b", "c", "d"]
    try:
        bfs_depth_limited(g, "a", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative max_depth must raise ValueError")
    try:
        bfs_depth_limited(g, "zzz", 2)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_50 OK")


if __name__ == "__main__":
    main()
