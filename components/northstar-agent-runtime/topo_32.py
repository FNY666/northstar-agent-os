"""Topological sort variant: DFS postorder output (T-32)."""
from __future__ import annotations
import ast

VERSION = "topo_32.v1"

def postorder(graph):
    visited = set()
    on_path = set()
    order = []
    bad = []
    def visit(u):
        if bad:
            return
        if u in on_path:
            bad.append(True)
            return
        if u in visited:
            return
        on_path.add(u)
        visited.add(u)
        for v in graph.get(u, []):
            visit(v)
        on_path.discard(u)
        order.append(u)
    for u in graph:
        visit(u)
    return None if bad else order

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
    assert postorder({1: [2], 2: [3], 3: []}) == [3, 2, 1]
    assert postorder({"a": ["b"], "b": ["a"]}) is None
    po = postorder({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert po[::-1][0] == "a" and po[0] == "d"
    assert stdlib_only()
    print("topo_32 OK")


if __name__ == "__main__":
    main()
