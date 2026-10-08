"""Iterative pre-order DFS with neighbor reversal. IS: explicit-stack pre-order that visits neighbors in adjacency order. IS NOT: post-order; see gtrav_08."""

from __future__ import annotations

import ast

VERSION = "gtrav-07.v1"

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

def dfs_preorder(graph: object, start: object) -> list:
    """Return nodes in pre-order using an explicit stack."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    seen: set = set()
    stack: list = [start]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        order.append(node)
        children = graph.get(node, [])
        for nxt in reversed(children):
            stack.append(nxt)
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
    g = {"a": ["b", "c"], "b": ["d"], "c": [], "d": []}
    assert dfs_preorder(g, "a") == ["a", "b", "d", "c"]
    assert dfs_preorder({"x": []}, "x") == ["x"]
    try:
        dfs_preorder(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    try:
        dfs_preorder({"a": [1.5]}, "a")
    except ValueError:
        pass
    else:
        raise AssertionError("non str/int neighbor must raise ValueError")
    assert stdlib_only()
    print("gtrav_07 OK")


if __name__ == "__main__":
    main()
