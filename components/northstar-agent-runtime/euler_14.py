"""Bridge detection by Tarjan lowlink (EULER-014), Real."""
from __future__ import annotations
import ast

VERSION = "euler-14.v1"

def find_bridges_tarjan(edges):
    """Tarjan lowlink bridge finding. Returns sorted edge indices."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))
    disc = {}
    low = {}
    timer = [0]
    bridges = []

    def dfs(u, pe):
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        for v, i in adj.get(u, ()):
            if i == pe:
                continue
            if v in disc:
                low[u] = min(low[u], disc[v])
            else:
                dfs(v, i)
                low[u] = min(low[u], low[v])
                if low[v] > disc[u]:
                    bridges.append(i)

    for u in adj:
        if u not in disc:
            dfs(u, -1)
    return sorted(bridges)

def main() -> None:
    line = [(0, 1), (1, 2), (2, 3)]
    assert find_bridges_tarjan(line) == [0, 1, 2]
    tri = [(0, 1), (1, 2), (2, 0)]
    assert find_bridges_tarjan(tri) == []
    barbell = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 5), (5, 3)]
    assert find_bridges_tarjan(barbell) == [3]
    assert find_bridges_tarjan([]) == []
    par = [(0, 1), (0, 1)]
    assert find_bridges_tarjan(par) == []
    assert stdlib_only()
    print("euler-14.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
