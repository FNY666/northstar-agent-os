"""DFS discovery order map. IS: maps each visited node to its discovery index. IS NOT: finish times; see gtrav_27."""

from __future__ import annotations

import ast

VERSION = "gtrav-43.v1"

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

def dfs_discovery_order(graph: object, start: object) -> dict:
    """Return {node: discovery_index} from DFS."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    disc: dict = {}
    seen: set = set()

    def visit(node: object) -> None:
        seen.add(node)
        disc[node] = len(disc)
        for nxt in graph.get(node, []):
            if nxt not in seen:
                visit(nxt)

    visit(start)
    return disc


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
    assert dfs_discovery_order(g, "a") == {"a": 0, "b": 1, "d": 2, "c": 3}
    assert dfs_discovery_order({"x": []}, "x") == {"x": 0}
    assert dfs_discovery_order({"a": ["b"], "b": [], "z": []}, "a") == {"a": 0, "b": 1}
    try:
        dfs_discovery_order(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_43 OK")


if __name__ == "__main__":
    main()
