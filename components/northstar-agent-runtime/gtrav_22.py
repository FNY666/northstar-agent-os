"""Topological sort via Kahn's algorithm (BFS). IS: linear order of a DAG, None when a cycle exists. IS NOT: DFS-based topo sort; see gtrav_23."""

from __future__ import annotations

import ast

VERSION = "gtrav-22.v1"

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

def kahn_toposort(graph: object) -> object:
    """Return a topological order, or None if the graph has a cycle."""
    graph = _req_graph(graph)
    nodes: set = set(graph)
    for vs in graph.values():
        nodes.update(vs)
    indeg: dict = {n: 0 for n in nodes}
    for vs in graph.values():
        for n in vs:
            indeg[n] += 1
    queue: list = [n for n in nodes if indeg[n] == 0]
    order: list = []
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nxt in graph.get(node, []):
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    if len(order) != len(nodes):
        return None
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
    order = kahn_toposort(g)
    assert order is not None
    pos = {n: i for i, n in enumerate(order)}
    assert pos["a"] < pos["b"] < pos["d"] and pos["a"] < pos["c"] < pos["d"]
    assert kahn_toposort({"a": ["b"], "b": ["a"]}) is None
    assert kahn_toposort({}) == []
    try:
        kahn_toposort({"a": "b"})
    except ValueError:
        pass
    else:
        raise AssertionError("non-list adjacency must raise ValueError")
    assert stdlib_only()
    print("gtrav_22 OK")


if __name__ == "__main__":
    main()
