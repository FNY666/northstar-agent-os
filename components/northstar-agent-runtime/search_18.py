"""BFS grid shortest path, Simulated.

What this IS: fewest-step path on a 4-directional binary grid (0 free, 1 blocked).

What this IS NOT: not for weighted terrain; use A* there.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import List, Optional, Tuple

#: Module version.
SEARCH_18_VERSION = "search-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-18.v1"


class SearchError(Exception):
    """Fail-closed."""


def bfs_grid_shortest(grid: List[List[int]], start: Tuple[int, int],
                      goal: Tuple[int, int]) -> Optional[int]:
    """Fewest steps from start to goal, or None if unreachable."""
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
    if start == goal:
        return 0
    queue = deque([(start[0], start[1], 0)])
    seen = {(start[0], start[1])}
    while queue:
        r, c, d = queue.popleft()
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if not ok(nr, nc) or (nr, nc) in seen:
                continue
            if (nr, nc) == goal:
                return d + 1
            seen.add((nr, nc))
            queue.append((nr, nc, d + 1))
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
    assert bfs_grid_shortest(open3, (0, 0), (2, 2)) == 4
    wall = [[0, 1, 0], [0, 1, 0], [0, 1, 0]]
    assert bfs_grid_shortest(wall, (0, 0), (0, 2)) is None
    assert bfs_grid_shortest(open3, (1, 1), (1, 1)) == 0
    assert stdlib_only()
    print("search-18.v1 OK")


if __name__ == "__main__":
    main()
