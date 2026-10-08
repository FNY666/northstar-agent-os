"""0-1 BFS for graphs with 0/1 edge weights. IS: shortest paths when every weight is 0 or 1. IS NOT: general Dijkstra; weights outside {0,1} raise."""

from __future__ import annotations

import ast

VERSION = "gtrav-31.v1"

def _req_wgraph(graph: object) -> dict:
    """Fail-closed: dict of node -> list of [neighbor, weight] with weight in {0, 1}."""
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
            nbr, w = item[0], item[1]
            if not isinstance(nbr, (str, int)):
                raise ValueError("neighbors must be str or int")
            if w not in (0, 1):
                raise ValueError("weights must be 0 or 1")
    return graph


def bfs_01(graph: object, start: object) -> dict:
    """Return {node: shortest distance} using 0-1 BFS."""
    graph = _req_wgraph(graph)
    if start not in graph:
        raise ValueError("start must be a node in graph")
    INF = 10 ** 18
    dist: dict = {start: 0}
    deq: list = [start]
    while deq:
        node = deq.pop(0)
        for nbr, w in graph.get(node, []):
            nd = dist[node] + w
            if nd < dist.get(nbr, INF):
                dist[nbr] = nd
                if w == 0:
                    deq.insert(0, nbr)
                else:
                    deq.append(nbr)
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
    g = {"a": [["b", 0], ["c", 1]], "b": [["d", 1]], "c": [["d", 0]], "d": []}
    assert bfs_01(g, "a") == {"a": 0, "b": 0, "c": 1, "d": 1}
    assert bfs_01({"x": []}, "x") == {"x": 0}
    try:
        bfs_01({"a": [["b", 2]]}, "a")
    except ValueError:
        pass
    else:
        raise AssertionError("weight 2 must raise ValueError")
    try:
        bfs_01({"a": [["b", 1]]}, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_31 OK")


if __name__ == "__main__":
    main()
