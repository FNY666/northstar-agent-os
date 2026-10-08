"""Swim in Rising Water: minimum time to swim from top-left to bottom-right IS: min-heap expansion keyed by max elevation so far IS NOT: binary search on time plus DFS"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-22.v1"

def _req_grid(value):
    if not isinstance(value, list) or not value or not isinstance(value[0], list):
        raise ValueError("grid must be a non-empty 2D list")
    n = len(value)
    out = []
    for i, row in enumerate(value):
        if not isinstance(row, list) or len(row) != n:
            raise ValueError(f"grid must be square; row {i} has wrong length")
        for v in row:
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError("grid must contain non-negative ints")
        out.append(list(row))
    return out


def swim_in_water(grid):
    """Return the minimum time to reach the bottom-right cell.

    Fail-closed: grid must be a square of non-negative ints,
    else :class:`ValueError`.
    """
    grid = _req_grid(grid)
    n = len(grid)
    seen = [[False] * n for _ in range(n)]
    heap = [(grid[0][0], 0, 0)]
    seen[0][0] = True
    while heap:
        t, r, c = heapq.heappop(heap)
        if (r, c) == (n - 1, n - 1):
            return t
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < n and 0 <= nc < n and not seen[nr][nc]:
                seen[nr][nc] = True
                heapq.heappush(heap, (max(t, grid[nr][nc]), nr, nc))
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
    assert swim_in_water([[0, 2], [1, 3]]) == 3
    assert swim_in_water([[0]]) == 0
    big = [[0, 1, 2, 3, 4], [24, 23, 22, 21, 5], [12, 13, 14, 15, 16],
           [11, 17, 18, 19, 20], [10, 9, 8, 7, 6]]
    assert swim_in_water(big) == 16
    try:
        swim_in_water([[0, 1], [2]])
    except ValueError:
        pass
    else:
        raise AssertionError("non-square grid must raise ValueError")
    assert stdlib_only()
    print("heap-22.v1 OK")


if __name__ == "__main__":
    main()
