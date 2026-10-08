"""Zigzag (spiral) level-order BFS. IS: levels alternate left-to-right and right-to-left. IS NOT: plain level order; see gtrav_06."""

from __future__ import annotations

import ast

VERSION = "gtrav-48.v1"

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

def bfs_zigzag(graph: object, start: object) -> list:
    """Return levels with alternating direction."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    levels: list = []
    seen: set = {start}
    current: list = [start]
    left_to_right = True
    while current:
        levels.append(list(current) if left_to_right else list(reversed(current)))
        nxt_level: list = []
        for node in current:
            for nxt in graph.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    nxt_level.append(nxt)
        current = nxt_level
        left_to_right = not left_to_right
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
    assert bfs_zigzag(g, "a") == [["a"], ["c", "b"], ["d"]]
    assert bfs_zigzag({"x": []}, "x") == [["x"]]
    assert bfs_zigzag({"a": ["b"], "b": [], "z": []}, "a") == [["a"], ["b"]]
    try:
        bfs_zigzag(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_48 OK")


if __name__ == "__main__":
    main()
