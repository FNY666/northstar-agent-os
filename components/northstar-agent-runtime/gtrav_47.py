"""Iterative post-order DFS with two stacks. IS: post-order without recursion. IS NOT: recursive post-order; see gtrav_08."""

from __future__ import annotations

import ast

VERSION = "gtrav-47.v1"

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

def dfs_postorder_two_stack(graph: object, start: object) -> list:
    """Return nodes in post-order using two stacks.

    The first stack holds (node, expanded) frames; the second stack
    collects finished nodes. Correct on DAGs, not just trees.
    """
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    seen: set = set()
    stack: list = [(start, False)]
    while stack:
        node, expanded = stack.pop()
        if expanded:
            order.append(node)
            continue
        if node in seen:
            continue
        seen.add(node)
        stack.append((node, True))
        for nxt in reversed(graph.get(node, [])):
            if nxt not in seen:
                stack.append((nxt, False))
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
    order = dfs_postorder_two_stack(g, "a")
    assert order[-1] == "a"
    assert order.index("d") < order.index("b")
    assert order.index("d") < order.index("c")
    assert order.index("b") < order.index("a")
    assert set(order) == {"a", "b", "c", "d"}
    assert dfs_postorder_two_stack({"x": []}, "x") == ["x"]
    try:
        dfs_postorder_two_stack(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_47 OK")


if __name__ == "__main__":
    main()
