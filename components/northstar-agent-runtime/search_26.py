"""A* grid search, Simulated.

What this IS: optimal grid path with Manhattan heuristic (4-dir, unit cost).

What this IS NOT: heuristic must be admissible; else use weighted A*.
"""

from __future__ import annotations

import ast
import heapq
from typing import List, Optional, Tuple

#: Module version.
SEARCH_26_VERSION = "search-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-26.v1"


class SearchError(Exception):
    """Fail-closed."""


def a_star_grid(grid: List[List[int]], start: Tuple[int, int],
                goal: Tuple[int, int]) -> Optional[List[Tuple[int, int]]]:
    """Optimal path on binary grid (0 free, 1 blocked), or None."""
    if grid is None:
        raise SearchError("grid required")
    rows = len(grid)
    if rows == 0:
        return None
    cols = len(grid[0])

    def ok(r: int, c: int) -> bool:
        return 0 <= r < rows and 0 <= c < cols and grid[r][c] == 0

    if not ok(*start) or not ok(*goal):
        return None

    def h(p: Tuple[int, int]) -> int:
        return abs(p[0] - goal[0]) + abs(p[1] - goal[1])

    openh = [(h(start), 0, start, [start])]
    best = {start: 0}
    while openh:
        _, g, node, path = heapq.heappop(openh)
        if node == goal:
            return path
        if g > best.get(node, float("inf")):
            continue
        r, c = node
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if not ok(nr, nc):
                continue
            ng = g + 1
            if ng < best.get((nr, nc), float("inf")):
                best[(nr, nc)] = ng
                heapq.heappush(openh, (ng + h((nr, nc)), ng, (nr, nc),
                                      path + [(nr, nc)]))
    return None

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    open3 = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    p = a_star_grid(open3, (0, 0), (2, 2))
    assert p is not None and len(p) == 5 and p[0] == (0, 0) and p[-1] == (2, 2)
    wall = [[0, 1, 0], [0, 1, 0], [0, 1, 0]]
    assert a_star_grid(wall, (0, 0), (0, 2)) is None
    assert stdlib_only()
    print("search-26.v1 OK")


if __name__ == "__main__":
    main()
