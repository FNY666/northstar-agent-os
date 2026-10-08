"""BFS that ignores edge weights. IS: treats [neighbor, weight] edges as unweighted adjacency. IS NOT: Dijkstra; weights never affect order."""

from __future__ import annotations

import ast

VERSION = "gtrav-46.v1"

def _req_wadj(graph: object) -> dict:
    """Fail-closed: dict of node -> list of [neighbor, weight] pairs."""
    if not isinstance(graph, dict):
        raise ValueError("graph must be a dict")
    for key, val in graph.items():
        if not isinstance(key, (str, int)):
            raise ValueError("node keys must be str or int")
        if not isinstance(val, list):
            raise ValueError("adjacency value must be a list")
        for item in val:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError("edges must be [neighbor, weight] pairs")
            if not isinstance(item[0], (str, int)):
                raise ValueError("neighbors must be str or int")
            if not isinstance(item[1], (int, float)):
                raise ValueError("weights must be numeric")
    return graph


def bfs_ignore_weights(graph: object, start: object) -> list:
    """Return BFS order ignoring the weight component of each edge."""
    graph = _req_wadj(graph)
    if start not in graph:
        raise ValueError("start must be a node in graph")
    order: list = []
    seen: set = {start}
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nbr, _w in graph.get(node, []):
            if nbr not in seen:
                seen.add(nbr)
                queue.append(nbr)
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
    g = {"a": [["b", 100], ["c", 1]], "b": [["d", 1]], "c": [["d", 100]], "d": []}
    assert bfs_ignore_weights(g, "a") == ["a", "b", "c", "d"]
    assert bfs_ignore_weights({"x": []}, "x") == ["x"]
    try:
        bfs_ignore_weights({"a": [["b", "heavy"]]}, "a")
    except ValueError:
        pass
    else:
        raise AssertionError("non-numeric weight must raise ValueError")
    try:
        bfs_ignore_weights(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_46 OK")


if __name__ == "__main__":
    main()
