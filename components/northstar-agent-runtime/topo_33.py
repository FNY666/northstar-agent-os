"""Topological sort variant: Kahn taking predecessor lists (T-33)."""
from __future__ import annotations
import ast

VERSION = "topo_33.v1"

def topo_sort_preds(preds):
    succ = {}
    indeg = {}
    for u in preds:
        succ.setdefault(u, [])
        indeg[u] = len(preds[u])
        for p in preds[u]:
            succ.setdefault(p, []).append(u)
            if p not in indeg:
                indeg[p] = 0
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in succ.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return order if len(order) == len(indeg) else None

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
    o = topo_sort_preds({"b": ["a"], "c": ["a"], "d": ["b", "c"], "a": []})
    assert o[0] == "a" and o[-1] == "d"
    assert topo_sort_preds({"a": ["b"], "b": ["a"]}) is None
    assert topo_sort_preds({"a": []}) == ["a"]
    assert stdlib_only()
    print("topo_33 OK")


if __name__ == "__main__":
    main()
