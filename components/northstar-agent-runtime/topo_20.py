"""Topological sort variant: course order from prerequisites (T-20)."""
from __future__ import annotations
import ast

VERSION = "topo_20.v1"

def find_order(n, prereqs):
    graph = {i: [] for i in range(n)}
    indeg = [0] * n
    for a, b in prereqs:
        graph[b].append(a)
        indeg[a] += 1
    queue = [i for i in range(n) if indeg[i] == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return order if len(order) == n else []

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
    assert find_order(2, [[1, 0]]) == [0, 1]
    assert find_order(2, [[1, 0], [0, 1]]) == []
    o = find_order(4, [[1, 0], [2, 0], [3, 1], [3, 2]])
    assert o[0] == 0 and o[-1] == 3 and set(o) == {0, 1, 2, 3}
    assert find_order(1, []) == [0]
    assert stdlib_only()
    print("topo_20 OK")


if __name__ == "__main__":
    main()
