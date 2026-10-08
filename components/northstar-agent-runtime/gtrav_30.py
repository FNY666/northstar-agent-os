"""DFS on the reversed graph. IS: traverses edges backwards (Kosaraju's first pass input). IS NOT: traversal of the original edge direction; see gtrav_02."""

from __future__ import annotations

import ast

VERSION = "gtrav-30.v1"

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

def _reversed(graph: dict) -> dict:
    rev: dict = {k: [] for k in graph}
    for k, vs in graph.items():
        for n in vs:
            rev.setdefault(n, []).append(k)
    return rev


def dfs_reverse_graph(graph: object, start: object) -> list:
    """Return DFS pre-order over reversed edges."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    rev = _reversed(graph)
    order: list = []
    seen: set = set()

    def visit(node: object) -> None:
        seen.add(node)
        order.append(node)
        for nxt in rev.get(node, []):
            if nxt not in seen:
                visit(nxt)

    visit(start)
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
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert dfs_reverse_graph(g, "c") == ["c", "b", "a"]
    assert dfs_reverse_graph(g, "a") == ["a"]
    assert dfs_reverse_graph({"x": []}, "x") == ["x"]
    try:
        dfs_reverse_graph(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_30 OK")


if __name__ == "__main__":
    main()
