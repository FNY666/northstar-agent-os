"""DFS region size, Simulated.

What this IS: flood-fill size of a connected free region on a grid.

What this IS NOT: not a path finder; counts reachable cells only.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

#: Module version.
SEARCH_19_VERSION = "search-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-19.v1"


class SearchError(Exception):
    """Fail-closed."""


def dfs_region_size(grid: List[List[int]], start: Tuple[int, int]) -> int:
    """Number of connected 0-cells reachable from start (4-dir)."""
    if grid is None:
        raise SearchError("grid required")
    rows = len(grid)
    if rows == 0:
        return 0
    cols = len(grid[0])
    sr, sc = start
    if not (0 <= sr < rows and 0 <= sc < cols) or grid[sr][sc] != 0:
        return 0
    stack = [(sr, sc)]
    seen = {(sr, sc)}
    while stack:
        r, c = stack.pop()
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if (0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] == 0
                    and (nr, nc) not in seen):
                seen.add((nr, nc))
                stack.append((nr, nc))
    return len(seen)

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
    g = [[0, 0, 1], [0, 1, 0], [1, 0, 0]]
    assert dfs_region_size(g, (0, 0)) == 3
    assert dfs_region_size(g, (0, 2)) == 0
    assert dfs_region_size([], (0, 0)) == 0
    assert stdlib_only()
    print("search-19.v1 OK")


if __name__ == "__main__":
    main()
