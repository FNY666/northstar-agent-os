"""Multi-source BFS. IS: BFS seeded from several start nodes at once. IS NOT: repeated single-source BFS; distances here are to the nearest source."""

from __future__ import annotations

import ast

VERSION = "gtrav-11.v1"

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

def bfs_multi_source(graph: object, starts: object) -> list:
    """Return BFS order from multiple sources."""
    graph = _req_graph(graph)
    if not isinstance(starts, list) or not starts:
        raise ValueError("starts must be a non-empty list")
    for s in starts:
        if s not in graph:
            raise ValueError("every start must be a node in graph")
    order: list = []
    seen: set = set(starts)
    queue: list = list(starts)
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nxt in graph.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
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
    assert bfs_multi_source(g, ["a", "d"]) == ["a", "d", "b", "c"]
    assert bfs_multi_source(g, ["b"]) == ["b", "d"]
    try:
        bfs_multi_source(g, [])
    except ValueError:
        pass
    else:
        raise AssertionError("empty starts must raise ValueError")
    try:
        bfs_multi_source(g, ["a", "zzz"])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_11 OK")


if __name__ == "__main__":
    main()
