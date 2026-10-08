"""BFS shortest path in an unweighted graph. IS: fewest-edges path from start to target, or None. IS NOT: weighted shortest path; use Dijkstra elsewhere."""

from __future__ import annotations

import ast

VERSION = "gtrav-09.v1"

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

def bfs_shortest_path(graph: object, start: object, target: object) -> object:
    """Return the shortest path list from start to target, or None."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    if start == target:
        return [start]
    seen: set = {start}
    queue: list = [(start, [start])]
    while queue:
        node, path = queue.pop(0)
        for nxt in graph.get(node, []):
            if nxt in seen:
                continue
            if nxt == target:
                return path + [nxt]
            seen.add(nxt)
            queue.append((nxt, path + [nxt]))
    return None


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
    assert bfs_shortest_path(g, "a", "d") == ["a", "b", "d"]
    assert bfs_shortest_path(g, "a", "a") == ["a"]
    assert bfs_shortest_path({"a": ["b"], "b": [], "z": []}, "a", "z") is None
    try:
        bfs_shortest_path(g, "a", "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown target must raise ValueError")
    assert stdlib_only()
    print("gtrav_09 OK")


if __name__ == "__main__":
    main()
