"""All simple paths via DFS with a cap. IS: enumerates simple paths up to max_paths. IS NOT: unbounded enumeration; the cap keeps it fail-safe."""

from __future__ import annotations

import ast

VERSION = "gtrav-12.v1"

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

def dfs_all_paths(graph: object, start: object, target: object, max_paths: object = 100) -> list:
    """Return up to max_paths simple paths from start to target."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    if not isinstance(max_paths, int) or max_paths < 1:
        raise ValueError("max_paths must be a positive int")
    paths: list = []

    def visit(node: object, path: list) -> None:
        if len(paths) >= max_paths:
            return
        if node == target:
            paths.append(list(path))
            return
        for nxt in graph.get(node, []):
            if nxt not in path:
                path.append(nxt)
                visit(nxt, path)
                path.pop()

    visit(start, [start])
    return paths


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
    assert dfs_all_paths(g, "a", "d") == [["a", "b", "d"], ["a", "c", "d"]]
    assert dfs_all_paths(g, "a", "d", max_paths=1) == [["a", "b", "d"]]
    assert dfs_all_paths({"a": ["b"], "b": [], "z": []}, "a", "z") == []
    try:
        dfs_all_paths(g, "a", "d", max_paths=0)
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive max_paths must raise ValueError")
    assert stdlib_only()
    print("gtrav_12 OK")


if __name__ == "__main__":
    main()
