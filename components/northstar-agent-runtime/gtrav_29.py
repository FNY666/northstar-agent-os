"""Bidirectional BFS on the undirected view. IS: searches from both ends and joins paths. IS NOT: directed bidirectional search; edges are treated as undirected."""

from __future__ import annotations

import ast

VERSION = "gtrav-29.v1"

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


def bfs_bidirectional(graph: object, start: object, target: object) -> object:
    """Return a path from start to target, or None."""
    graph = _req_graph(graph)
    _req_start(graph, start)
    if target not in graph:
        raise ValueError("target must be a node in graph")
    if start == target:
        return [start]
    u = _undirected(graph)
    qf: list = [start]
    qb: list = [target]
    pf: dict = {start: None}
    pb: dict = {target: None}

    def expand(queue: list, mine: dict, theirs: dict) -> object:
        nxt_q: list = []
        for node in queue:
            for nb in u.get(node, []):
                if nb in mine:
                    continue
                mine[nb] = node
                if nb in theirs:
                    return nb
                nxt_q.append(nb)
        queue[:] = nxt_q
        return None

    while qf and qb:
        meet = expand(qf, pf, pb)
        if meet is None:
            meet = expand(qb, pb, pf)
        if meet is not None:
            fwd: list = []
            n: object = meet
            while n is not None:
                fwd.append(n)
                n = pf[n]
            fwd.reverse()
            n = pb[meet]
            while n is not None:
                fwd.append(n)
                n = pb[n]
            return fwd
    return None


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
    p = bfs_bidirectional(g, "a", "d")
    assert p is not None and p[0] == "a" and p[-1] == "d" and len(p) == 3
    assert bfs_bidirectional(g, "a", "a") == ["a"]
    assert bfs_bidirectional({"a": ["b"], "b": [], "z": []}, "a", "z") is None
    try:
        bfs_bidirectional(g, "a", "zzz")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown target must raise ValueError")
    assert stdlib_only()
    print("gtrav_29 OK")


if __name__ == "__main__":
    main()
