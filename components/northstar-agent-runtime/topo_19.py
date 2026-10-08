"""Topological sort variant: course-schedule feasibility check (T-19)."""
from __future__ import annotations
import ast

VERSION = "topo_19.v1"

def can_finish(n, prereqs):
    graph = {i: [] for i in range(n)}
    indeg = {i: 0 for i in range(n)}
    for a, b in prereqs:
        graph[b].append(a)
        indeg[a] += 1
    queue = [i for i in range(n) if indeg[i] == 0]
    done = 0
    while queue:
        u = queue.pop(0)
        done += 1
        for v in graph[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return done == n

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
    assert can_finish(2, [[1, 0]]) is True
    assert can_finish(2, [[1, 0], [0, 1]]) is False
    assert can_finish(3, []) is True
    assert can_finish(1, [[0, 0]]) is False
    assert stdlib_only()
    print("topo_19 OK")


if __name__ == "__main__":
    main()
