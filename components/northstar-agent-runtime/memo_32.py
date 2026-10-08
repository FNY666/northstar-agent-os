"""Memoized Min Path Sum: memoization example.

Cheapest top-left to bottom-right path moving only right/down: grid[i][j] + min(down, right). The (i, j) cache gives O(m*n).

What this IS: a real memoized min-path-sum solver over an (i, j) cache.
What this IS NOT: a path reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_32_VERSION = "memo-min-path-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-min-path-sum.v1"


class MemoError(Exception):
    """Fail-closed."""


def min_path_sum(grid: tuple, i: int = 0, j: int = 0, _cache: dict | None = None) -> float:
    """Memoized min path sum."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    m = len(grid)
    n = len(grid[0])
    if i == m - 1 and j == n - 1:
        cache[key] = grid[i][j]
    else:
        down = min_path_sum(grid, i + 1, j, cache) if i + 1 < m else float("inf")
        right = min_path_sum(grid, i, j + 1, cache) if j + 1 < n else float("inf")
        cache[key] = grid[i][j] + min(down, right)
    return cache[key]

def test_min_path_sum_example():
    assert min_path_sum(((1, 3, 1), (1, 5, 1), (4, 2, 1))) == 7


def test_min_path_sum_single():
    assert min_path_sum(((5,),)) == 5


def test_min_path_sum_row():
    assert min_path_sum(((1, 2, 3),)) == 6

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_min_path_sum_example()
    test_min_path_sum_single()
    test_min_path_sum_row()
    assert stdlib_only()
    print("memo-32 OK: min-path-sum")


if __name__ == "__main__":
    main()
