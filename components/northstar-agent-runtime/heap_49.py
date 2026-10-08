"""Minimum Time to Visit a Cell In a Grid: minimum time to reach the bottom-right cell with wait rules IS: min-heap Dijkstra with parity-aware waiting IS NOT: BFS over time steps"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-49.v1"

def _req_grid(value):
    if not isinstance(value, list) or not value or not isinstance(value[0], list):
        raise ValueError("grid must be a non-empty 2D list")
    w = len(value[0])
    out = []
    for i, row in enumerate(value):
        if not isinstance(row, list) or len(row) != w:
            raise ValueError(f"row {i} must be a list of length {w}")
        for v in row:
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError("grid must contain non-negative ints")
        out.append(list(row))
    return out


def minimum_time(grid):
    """Return the minimum time to reach the bottom-right, else -1.

    Fail-closed: grid must be a rectangular grid of non-negative ints,
    else :class:`ValueError`.
    """
    grid = _req_grid(grid)
    rows, cols = len(grid), len(grid[0])
    if rows > 1 and cols > 1 and grid[0][1] > 1 and grid[1][0] > 1:
        return -1
    INF = float("inf")
    dist = [[INF] * cols for _ in range(rows)]
    dist[0][0] = 0
    heap = [(0, 0, 0)]
    while heap:
        t, r, c = heapq.heappop(heap)
        if (r, c) == (rows - 1, cols - 1):
            return t
        if t > dist[r][c]:
            continue
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                nt = t + 1
                if grid[nr][nc] > nt:
                    nt += (grid[nr][nc] - nt + 1) // 2 * 2
                if nt < dist[nr][nc]:
                    dist[nr][nc] = nt
                    heapq.heappush(heap, (nt, nr, nc))
    return -1

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert minimum_time([[0, 1, 3, 2], [5, 1, 2, 5], [4, 3, 8, 6]]) == 7
    assert minimum_time([[0, 2, 4], [3, 2, 1], [1, 0, 4]]) == -1
    assert minimum_time([[0]]) == 0
    try:
        minimum_time([[0, 1], [2]])
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    assert stdlib_only()
    print("heap-49.v1 OK")


if __name__ == "__main__":
    main()
