"""Path With Minimum Effort: minimize the maximum height difference along a path IS: Dijkstra-like expansion with a min-heap keyed by effort IS NOT: binary search on effort plus BFS"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-18.v1"

def _req_grid(value):
    if not isinstance(value, list) or not value or not isinstance(value[0], list):
        raise ValueError("heights must be a non-empty 2D list")
    w = len(value[0])
    out = []
    for i, row in enumerate(value):
        if not isinstance(row, list) or len(row) != w:
            raise ValueError(f"row {i} must be a list of length {w}")
        for v in row:
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise ValueError("heights must be non-negative numbers")
        out.append(list(row))
    return out


def minimum_effort_path(heights):
    """Return the minimum effort from top-left to bottom-right.

    Fail-closed: heights must be a non-empty rectangular grid of
    non-negative numbers, else :class:`ValueError`.
    """
    heights = _req_grid(heights)
    rows, cols = len(heights), len(heights[0])
    best = [[float("inf")] * cols for _ in range(rows)]
    best[0][0] = 0
    heap = [(0, 0, 0)]
    while heap:
        effort, r, c = heapq.heappop(heap)
        if (r, c) == (rows - 1, cols - 1):
            return effort
        if effort > best[r][c]:
            continue
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                ne = max(effort, abs(heights[nr][nc] - heights[r][c]))
                if ne < best[nr][nc]:
                    best[nr][nc] = ne
                    heapq.heappush(heap, (ne, nr, nc))
    return best[rows - 1][cols - 1]

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
    assert minimum_effort_path([[1, 2, 2], [3, 8, 2], [5, 3, 5]]) == 2
    assert minimum_effort_path([[1, 2, 3], [3, 8, 4], [5, 3, 5]]) == 1
    assert minimum_effort_path([[7]]) == 0
    try:
        minimum_effort_path([[1, 2], [3]])
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    assert stdlib_only()
    print("heap-18.v1 OK")


if __name__ == "__main__":
    main()
