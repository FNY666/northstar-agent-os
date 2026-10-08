"""Iterative deepening DFS. IS: depth-limited DFS repeated for increasing limits; returns a path or None. IS NOT: unbounded DFS; the depth cap is mandatory."""

from __future__ import annotations

import ast

VERSION = "gtrav-28.v1"

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

def iddfs(graph: object, start: object, target: object, max_depth: object) -> object:
    """Return a path from start to target within max_depth, or None."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    if not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative int")

    def dls(node: object, limit: int, path: list, seen: set) -> object:
        if node == target:
            return list(path)
        if limit == 0:
            return None
        for nxt in graph.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                path.append(nxt)
                found = dls(nxt, limit - 1, path, seen)
                if found is not None:
                    return found
                path.pop()
                seen.discard(nxt)
        return None

    for depth in range(max_depth + 1):
        found = dls(start, depth, [start], {start})
        if found is not None:
            return found
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
    assert iddfs(g, "a", "d", 2) == ["a", "b", "d"]
    assert iddfs(g, "a", "d", 1) is None
    assert iddfs(g, "a", "a", 0) == ["a"]
    try:
        iddfs(g, "a", "d", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative max_depth must raise ValueError")
    try:
        iddfs(g, "a", "zzz", 3)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown target must raise ValueError")
    assert stdlib_only()
    print("gtrav_28 OK")


if __name__ == "__main__":
    main()
