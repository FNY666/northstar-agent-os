"""Topological sort variant: DFS with memoized successor lookup (T-35)."""
from __future__ import annotations
import ast
import functools
VERSION = "topo_35.v1"

import functools

def topo_sort(graph):
    @functools.lru_cache(maxsize=None)
    def deps(u):
        return tuple(graph.get(u, ()))
    visited = set()
    on_path = set()
    order = []
    bad = []
    def visit(u):
        if bad or u in visited:
            return
        if u in on_path:
            bad.append(True)
            return
        on_path.add(u)
        for v in deps(u):
            visit(v)
        on_path.discard(u)
        visited.add(u)
        order.append(u)
    for u in graph:
        visit(u)
    return None if bad else order[::-1]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert topo_sort({1: [2], 2: [3], 3: []}) == [1, 2, 3]
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    o = topo_sort({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert o[0] == "a" and o[-1] == "d"
    assert stdlib_only()
    print("topo_35 OK")


if __name__ == "__main__":
    main()
