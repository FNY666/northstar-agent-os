"""Topological sort variant: sink peeling from the outside in (T-36)."""
from __future__ import annotations
import ast

VERSION = "topo_36.v1"

def peel_order(graph):
    succ = {u: set(graph.get(u, [])) for u in graph}
    for u in graph:
        for v in graph[u]:
            succ.setdefault(v, set())
    outdeg = {u: len(succ[u]) for u in succ}
    pred = {}
    for u in succ:
        for v in succ[u]:
            pred.setdefault(v, []).append(u)
    cur = [u for u, d in outdeg.items() if d == 0]
    layers = []
    done = 0
    while cur:
        layers.append(sorted(cur))
        done += len(cur)
        nxt = []
        for u in cur:
            for p in pred.get(u, []):
                outdeg[p] -= 1
                if outdeg[p] == 0:
                    nxt.append(p)
        cur = nxt
    if done != len(succ):
        return None
    return layers

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
    assert peel_order({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) == [["d"], ["b", "c"], ["a"]]
    assert peel_order({1: [2], 2: [3], 3: []}) == [[3], [2], [1]]
    assert peel_order({"a": ["b"], "b": ["a"]}) is None
    assert stdlib_only()
    print("topo_36 OK")


if __name__ == "__main__":
    main()
