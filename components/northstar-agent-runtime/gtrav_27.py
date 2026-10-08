"""DFS discovery/finish times. IS: returns (discovery, finish) timestamp dicts. IS NOT: a visit order; see gtrav_02."""

from __future__ import annotations

import ast

VERSION = "gtrav-27.v1"

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

def dfs_times(graph: object, start: object) -> tuple:
    """Return (discovery, finish) dicts for DFS from start."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    disc: dict = {}
    fin: dict = {}
    seen: set = set()
    clock = [0]

    def visit(node: object) -> None:
        seen.add(node)
        disc[node] = clock[0]
        clock[0] += 1
        for nxt in graph.get(node, []):
            if nxt not in seen:
                visit(nxt)
        fin[node] = clock[0]
        clock[0] += 1

    visit(start)
    return (disc, fin)


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
    disc, fin = dfs_times(g, "a")
    assert disc == {"a": 0, "b": 1, "d": 2, "c": 5}
    assert fin == {"d": 3, "b": 4, "c": 6, "a": 7}
    assert all(disc[n] < fin[n] for n in disc)
    assert fin["a"] == 7
    d2, f2 = dfs_times({"x": []}, "x")
    assert d2 == {"x": 0} and f2 == {"x": 1}
    try:
        dfs_times(g, "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown start must raise ValueError")
    assert stdlib_only()
    print("gtrav_27 OK")


if __name__ == "__main__":
    main()
