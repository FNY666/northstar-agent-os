"""DFS first-found path. IS: depth-first path from start to target, or None. IS NOT: the shortest path; see gtrav_09."""

from __future__ import annotations

import ast

VERSION = "gtrav-10.v1"

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

def dfs_find_path(graph: object, start: object, target: object) -> object:
    """Return a DFS path from start to target, or None."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    seen: set = set()

    def visit(node: object) -> object:
        if node == target:
            return [node]
        seen.add(node)
        for nxt in graph.get(node, []):
            if nxt not in seen:
                sub = visit(nxt)
                if sub is not None:
                    return [node] + sub
        return None

    return visit(start)


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
    p = dfs_find_path(g, "a", "d")
    assert p == ["a", "b", "d"]
    assert dfs_find_path(g, "a", "a") == ["a"]
    assert dfs_find_path({"a": ["b"], "b": [], "z": []}, "a", "z") is None
    try:
        dfs_find_path(g, "zzz", "d")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_10 OK")


if __name__ == "__main__":
    main()
