"""lis-41: Longest increasing path in a matrix.

DFS with memoization over 4-neighbour moves to larger cells.

Time complexity: O(R*C) time
Space complexity: O(R*C)"""

import ast
import sys
from functools import lru_cache
LIS_41_VERSION = "lis-41.v1"


def _check_matrix(matrix):
    """Validate a rectangular matrix of numbers."""
    if not isinstance(matrix, (list, tuple)):
        raise ValueError("matrix must be a list or tuple")
    grid = []
    for row in matrix:
        if not isinstance(row, (list, tuple)):
            raise ValueError("matrix rows must be lists or tuples")
        for x in row:
            if not isinstance(x, (int, float)):
                raise ValueError("matrix elements must be numbers")
        grid.append(list(row))
    if grid and any(len(r) != len(grid[0]) for r in grid):
        raise ValueError("matrix rows must have equal length")
    return grid
def longest_increasing_path(matrix):
    """Length of the longest strictly increasing 4-directional path."""
    grid = _check_matrix(matrix)
    if not grid or not grid[0]:
        return 0
    rows, cols = len(grid), len(grid[0])

    @lru_cache(maxsize=None)
    def dfs(r, c):
        best = 1
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] > grid[r][c]:
                v = dfs(nr, nc) + 1
                if v > best:
                    best = v
        return best

    return max(dfs(r, c) for r in range(rows) for c in range(cols))

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert longest_increasing_path([[9, 9, 4], [6, 6, 8], [2, 1, 1]]) == 4
    assert longest_increasing_path([[3, 4, 5], [3, 2, 6], [2, 2, 1]]) == 4
    assert longest_increasing_path([]) == 0
    assert stdlib_only()
    print("lis-41 OK")


if __name__ == "__main__":
    main()
