"""Memoized Dungeon Game: memoization example.

Minimum starting health to survive: need(i,j) = max(1, min(need(down), need(right)) - grid[i][j]). The (i, j) cache gives O(m*n).

What this IS: a real memoized min-health solver, never returning less than 1.
What this IS NOT: a path reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_33_VERSION = "memo-dungeon-game.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-dungeon-game.v1"


class MemoError(Exception):
    """Fail-closed."""


def dungeon(grid: tuple, i: int = 0, j: int = 0, _cache: dict | None = None) -> float:
    """Memoized minimum starting health."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    m = len(grid)
    n = len(grid[0])
    if i == m - 1 and j == n - 1:
        cache[key] = max(1, 1 - grid[i][j])
    else:
        down = dungeon(grid, i + 1, j, cache) if i + 1 < m else float("inf")
        right = dungeon(grid, i, j + 1, cache) if j + 1 < n else float("inf")
        cache[key] = max(1, min(down, right) - grid[i][j])
    return cache[key]

def test_dungeon_example():
    assert dungeon(((-2, -3, 3), (-5, -10, 1), (10, 30, -5))) == 7


def test_dungeon_single_positive():
    assert dungeon(((5,),)) == 1


def test_dungeon_single_negative():
    assert dungeon(((-5,),)) == 6

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
    test_dungeon_example()
    test_dungeon_single_positive()
    test_dungeon_single_negative()
    assert stdlib_only()
    print("memo-33 OK: dungeon-game")


if __name__ == "__main__":
    main()
