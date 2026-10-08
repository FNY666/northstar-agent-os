"""Connected components via BFS (undirected view). IS: partitions nodes into components treating edges as undirected. IS NOT: strongly connected components of a directed graph."""

from __future__ import annotations

import ast

VERSION = "gtrav-19.v1"

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

def _undirected(graph: dict) -> dict:
    u: dict = {k: list(v) for k, v in graph.items()}
    for k, vs in graph.items():
        for n in vs:
            u.setdefault(n, [])
            if k not in u[n]:
                u[n].append(k)
    return u


def bfs_components(graph: object) -> list:
    """Return connected components as sorted lists."""
    graph = _req_graph(graph)
    u = _undirected(graph)
    seen: set = set()
    comps: list = []
    for root in u:
        if root in seen:
            continue
        comp: list = []
        queue: list = [root]
        seen.add(root)
        while queue:
            node = queue.pop(0)
            comp.append(node)
            for nxt in u.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        comps.append(sorted(comp, key=str))
    return comps


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
    g = {"a": ["b"], "b": ["a"], "c": []}
    assert bfs_components(g) == [["a", "b"], ["c"]]
    assert bfs_components({"x": []}) == [["x"]]
    assert bfs_components({}) == []
    try:
        bfs_components("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    assert stdlib_only()
    print("gtrav_19 OK")


if __name__ == "__main__":
    main()
