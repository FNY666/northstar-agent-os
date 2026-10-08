"""BFS level count. IS: number of BFS layers from start. IS NOT: the levels themselves; see gtrav_06."""

from __future__ import annotations

import ast

VERSION = "gtrav-42.v1"

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

def bfs_level_count(graph: object, start: object) -> int:
    """Return the number of BFS levels reachable from start."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    seen: set = {start}
    current: list = [start]
    levels = 0
    while current:
        levels += 1
        nxt_level: list = []
        for node in current:
            for nxt in graph.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    nxt_level.append(nxt)
        current = nxt_level
    return levels


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
    assert bfs_level_count(g, "a") == 3
    assert bfs_level_count({"x": []}, "x") == 1
    assert bfs_level_count({"a": ["b"], "b": [], "z": []}, "a") == 2
    try:
        bfs_level_count(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_42 OK")


if __name__ == "__main__":
    main()
