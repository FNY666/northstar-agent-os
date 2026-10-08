"""DFS with an explicit stack of iterators. IS: simulates recursion with (node, next-child-index) frames. IS NOT: the simple push/pop stack DFS; see gtrav_03."""

from __future__ import annotations

import ast

VERSION = "gtrav-14.v1"

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

def dfs_explicit_iterators(graph: object, start: object) -> list:
    """Return pre-order using explicit iterator frames."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    order: list = []
    seen: set = {start}
    stack: list = [[start, 0]]
    order.append(start)
    while stack:
        frame = stack[-1]
        node, idx = frame[0], frame[1]
        children = graph.get(node, [])
        if idx >= len(children):
            stack.pop()
            continue
        frame[1] = idx + 1
        nxt = children[idx]
        if nxt not in seen:
            seen.add(nxt)
            order.append(nxt)
            stack.append([nxt, 0])
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
    assert dfs_explicit_iterators(g, "a") == ["a", "b", "d", "c"]
    assert dfs_explicit_iterators({"x": []}, "x") == ["x"]
    assert dfs_explicit_iterators({"a": ["b"], "b": [], "z": []}, "a") == ["a", "b"]
    try:
        dfs_explicit_iterators(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_14 OK")


if __name__ == "__main__":
    main()
