"""Breadth-first traversal, naive dequeue-marked. IS: level-order visit where a node is marked visited when dequeued (may enqueue duplicates on dense graphs). IS NOT: the enqueue-marked optimization; see gtrav_04."""

from __future__ import annotations

import ast

VERSION = "gtrav-01.v1"

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

def bfs_iterative(graph: object, start: object) -> list:
    """Return nodes in BFS order, marking visited on dequeue."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    seen: set = set()
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        if node in seen:
            continue
        seen.add(node)
        order.append(node)
        queue.extend(graph.get(node, []))
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
    assert bfs_iterative(g, "a") == ["a", "b", "c", "d"]
    assert bfs_iterative({"x": []}, "x") == ["x"]
    assert bfs_iterative({"a": ["b"], "b": [], "z": []}, "a") == ["a", "b"]
    try:
        bfs_iterative(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    try:
        bfs_iterative(["a", "b"], "a")
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    assert stdlib_only()
    print("gtrav_01 OK")


if __name__ == "__main__":
    main()
