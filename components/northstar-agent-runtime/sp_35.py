"""IDA* iterative deepening A* on grid (SP-035), Real."""
from __future__ import annotations
import ast

VERSION = "sp-35.v1"

INF = float("inf")

def ida_star(grid, src, dst):
    R, C = len(grid), len(grid[0])
    def h(r, c):
        return abs(r - dst[0]) + abs(c - dst[1])
    bound = h(*src)
    path = [src]
    visited = {src}
    while True:
        t = _search(grid, path, visited, 0, bound, h, dst)
        if t == "FOUND":
            return len(path) - 1
        if t == INF:
            return INF
        bound = t

def _search(grid, path, visited, g, bound, h, dst):
    R, C = len(grid), len(grid[0])
    r, c = path[-1]
    f = g + h(r, c)
    if f > bound:
        return f
    if (r, c) == dst:
        return "FOUND"
    minb = INF
    for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        nr, nc = r + dr, c + dc
        if 0 <= nr < R and 0 <= nc < C and grid[nr][nc] == 0 and (nr, nc) not in visited:
            visited.add((nr, nc))
            path.append((nr, nc))
            t = _search(grid, path, visited, g + 1, bound, h, dst)
            if t == "FOUND":
                return "FOUND"
            if t < minb:
                minb = t
            path.pop()
            visited.discard((nr, nc))
    return minb

def main() -> None:
    g = [[0, 0], [0, 0]]
    assert ida_star(g, (0, 0), (1, 1)) == 2
    g2 = [[0, 1, 0], [0, 1, 0], [0, 0, 0]]
    assert ida_star(g2, (0, 0), (0, 2)) == 6
    assert ida_star([[0]], (0, 0), (0, 0)) == 0
    g3 = [[0, 1], [1, 0]]
    assert ida_star(g3, (0, 0), (1, 1)) == INF
    assert stdlib_only()
    print("sp-35 OK")

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
