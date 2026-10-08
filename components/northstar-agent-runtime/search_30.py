"""IDA* (simplified mock), Simulated.

What this IS: mock iterative-deepening A* with f-cost threshold on a grid.

What this IS NOT: mock/simplified simulation; not a production pathfinder.
"""

from __future__ import annotations

import ast
from typing import List, Optional, Tuple

#: Module version.
SEARCH_30_VERSION = "search-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-30.v1"


class SearchError(Exception):
    """Fail-closed."""


def _ida_dfs(node, goal, g, threshold, h, ok, path, seen):
    f = g + h(node)
    if f > threshold:
        return None, f
    if node == goal:
        return path, threshold
    min_t = float("inf")
    r, c = node
    for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        nb = (r + dr, c + dc)
        if not ok(*nb) or nb in seen:
            continue
        seen.add(nb)
        res, t = _ida_dfs(nb, goal, g + 1, threshold, h, ok, path + [nb], seen)
        seen.discard(nb)
        if res:
            return res, t
        if t < min_t:
            min_t = t
    return None, min_t


def ida_star(grid: List[List[int]], start: Tuple[int, int],
             goal: Tuple[int, int]) -> Optional[List[Tuple[int, int]]]:
    """Mock IDA*: path on binary grid, or None."""
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

    threshold = h(start)
    while True:
        found, new_t = _ida_dfs(start, goal, 0, threshold, h, ok, [start], {start})
        if found:
            return found
        if new_t == float("inf"):
            return None
        threshold = new_t

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
    p = ida_star(open3, (0, 0), (2, 2))
    assert p is not None and p[0] == (0, 0) and p[-1] == (2, 2)
    assert ida_star([[0, 1], [1, 0]], (0, 0), (1, 1)) is None
    assert stdlib_only()
    print("search-30.v1 OK")


if __name__ == "__main__":
    main()
