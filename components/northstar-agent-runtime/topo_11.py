"""Topological sort variant: Kahn taking an adjacency matrix (T-11)."""
from __future__ import annotations
import ast

VERSION = "topo_11.v1"

def topo_sort_matrix(nodes, matrix):
    n = len(nodes)
    indeg = [0] * n
    for i in range(n):
        for j in range(n):
            if matrix[i][j]:
                indeg[j] += 1
    queue = [i for i in range(n) if indeg[i] == 0]
    order = []
    while queue:
        i = queue.pop(0)
        order.append(nodes[i])
        for j in range(n):
            if matrix[i][j]:
                indeg[j] -= 1
                if indeg[j] == 0:
                    queue.append(j)
    return order if len(order) == n else None

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
    assert topo_sort_matrix(["a", "b", "c"], [[0, 1, 1], [0, 0, 1], [0, 0, 0]]) == ["a", "b", "c"]
    assert topo_sort_matrix(["a", "b"], [[0, 1], [1, 0]]) is None
    assert topo_sort_matrix([], []) == []
    assert topo_sort_matrix(["x"], [[0]]) == ["x"]
    assert stdlib_only()
    print("topo_11 OK")


if __name__ == "__main__":
    main()
