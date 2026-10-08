"""Topological sort variant: DFS on implicit graph via neighbor function (T-22)."""
from __future__ import annotations
import ast

VERSION = "topo_22.v1"

def topo_sort(nodes, neighbors):
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
        for v in neighbors(u):
            visit(v)
        on_path.discard(u)
        visited.add(u)
        order.append(u)
    for u in nodes:
        visit(u)
    return None if bad else order[::-1]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    nb = {"a": ["b"], "b": ["c"], "c": []}
    assert topo_sort(["a", "b", "c"], lambda u: nb[u]) == ["a", "b", "c"]
    assert topo_sort(["a"], lambda u: ["a"]) is None
    assert topo_sort([], lambda u: []) == []
    assert stdlib_only()
    print("topo_22 OK")


if __name__ == "__main__":
    main()
