"""DFS edge classification on the undirected view. IS: labels each traversed edge tree or back. IS NOT: directed edge classification (forward/cross)."""

from __future__ import annotations

import ast

VERSION = "gtrav-45.v1"

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


def dfs_edge_classes(graph: object, start: object) -> dict:
    """Return {(u, v): 'tree'|'back'} for the undirected DFS tree."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    u = _undirected(graph)
    classes: dict = {}
    seen: set = set()
    disc: dict = {}

    def visit(node: object, parent: object) -> None:
        seen.add(node)
        disc[node] = len(disc)
        for nxt in u.get(node, []):
            if nxt not in seen:
                classes[(node, nxt)] = "tree"
                visit(nxt, node)
            elif nxt != parent and disc.get(nxt, -1) < disc[node]:
                classes[(node, nxt)] = "back"

    visit(start, None)
    return classes


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
    cls = dfs_edge_classes(g, "a")
    trees = [e for e, c in cls.items() if c == "tree"]
    backs = [e for e, c in cls.items() if c == "back"]
    assert len(trees) == 3
    assert len(backs) == 1
    assert ("a", "b") in cls and cls[("a", "b")] == "tree"
    cls2 = dfs_edge_classes({"x": []}, "x")
    assert cls2 == {}
    try:
        dfs_edge_classes(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_45 OK")


if __name__ == "__main__":
    main()
