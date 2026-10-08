"""Topological sort variant: enumerating all topological orders (T-25)."""
from __future__ import annotations
import ast

VERSION = "topo_25.v1"

def all_orders(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    res = []
    def bt(path):
        if len(path) == len(indeg):
            res.append(list(path))
            return
        for u in indeg:
            if indeg[u] == 0 and u not in path:
                path.append(u)
                touched = []
                for v in graph.get(u, []):
                    indeg[v] -= 1
                    touched.append(v)
                bt(path)
                for v in touched:
                    indeg[v] += 1
                path.pop()
    bt([])
    return res

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
    assert len(all_orders({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})) == 2
    assert all_orders({1: [2], 2: [3], 3: []}) == [[1, 2, 3]]
    assert all_orders({"a": ["b"], "b": ["a"]}) == []
    assert len(all_orders({"a": [], "b": []})) == 2
    assert stdlib_only()
    print("topo_25 OK")


if __name__ == "__main__":
    main()
