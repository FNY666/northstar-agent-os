"""Bridge detection by reachability count (EULER-013), Real."""
from __future__ import annotations
import ast

VERSION = "euler-13.v1"

def find_bridges(edges):
    """Return sorted list of edge indices that are bridges (undirected)."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))

    def reach(src, skip):
        seen = {src}
        stack = [src]
        while stack:
            u = stack.pop()
            for v, i in adj.get(u, ()):
                if i == skip or v in seen:
                    continue
                seen.add(v)
                stack.append(v)
        return seen

    bridges = []
    for i, (u, v) in enumerate(edges):
        if v not in reach(u, i):
            bridges.append(i)
    return sorted(bridges)

def main() -> None:
    line = [(0, 1), (1, 2), (2, 3)]
    assert find_bridges(line) == [0, 1, 2]
    tri = [(0, 1), (1, 2), (2, 0)]
    assert find_bridges(tri) == []
    barbell = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 5), (5, 3)]
    assert find_bridges(barbell) == [3]
    assert find_bridges([]) == []
    par = [(0, 1), (0, 1)]
    assert find_bridges(par) == []
    assert stdlib_only()
    print("euler-13.v1 OK")

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
