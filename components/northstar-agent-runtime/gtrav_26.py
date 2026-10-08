"""BFS distance map. IS: maps each reachable node to its fewest-edges distance. IS NOT: weighted distances; all edges count as 1."""

from __future__ import annotations

import ast

VERSION = "gtrav-26.v1"

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

def bfs_distances(graph: object, start: object) -> dict:
    """Return {node: distance} from start."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    dist: dict = {start: 0}
    queue: list = [start]
    while queue:
        node = queue.pop(0)
        for nxt in graph.get(node, []):
            if nxt not in dist:
                dist[nxt] = dist[node] + 1
                queue.append(nxt)
    return dist


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
    assert bfs_distances(g, "a") == {"a": 0, "b": 1, "c": 1, "d": 2}
    assert bfs_distances({"a": ["b"], "b": [], "z": []}, "a") == {"a": 0, "b": 1}
    assert bfs_distances({"x": []}, "x") == {"x": 0}
    try:
        bfs_distances(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_26 OK")


if __name__ == "__main__":
    main()
