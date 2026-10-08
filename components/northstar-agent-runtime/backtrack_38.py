"""Backtracking: domino tiling counter for small boards (mock).

IS: counts exact tilings of a small rectangular board (with optional
    blocked cells) by 1x2 dominoes, via backtracking that always covers
    the first free cell.
IS NOT: a tromino/polyomino tiler, a maximum-matching solver, or a
    large-board counting engine (exponential in the worst case).
"""

from __future__ import annotations

import ast
from typing import List, Tuple

VERSION = "backtrack_38.v1"

Cell = Tuple[int, int]


def count_tilings(board: List[str]) -> int:
    """Count domino tilings of the free ('.') cells; '#' cells are blocked."""
    if not board:
        raise ValueError("board must be non-empty")
    rows, cols = len(board), len(board[0])
    for row in board:
        if len(row) != cols:
            raise ValueError("board rows must all have the same length")
        for ch in row:
            if ch not in ".#":
                raise ValueError("bad cell %r" % ch)

    free = {(r, c) for r in range(rows) for c in range(cols) if board[r][c] == "."}
    if len(free) % 2:
        return 0
    covered = set()
    count = 0

    def bt() -> None:
        nonlocal count
        if len(covered) == len(free):
            count += 1
            return
        r, c = min(free - covered)
        for dr, dc in ((0, 1), (1, 0)):
            nr, nc = r + dr, c + dc
            if (nr, nc) in free and (nr, nc) not in covered:
                covered.add((r, c))
                covered.add((nr, nc))
                bt()
                covered.discard((r, c))
                covered.discard((nr, nc))

    bt()
    return count


def stdlib_only() -> bool:
    """Parse this file with ast; True only if every import is allowed."""
    allowed = {"__future__", "ast", "typing"}
    with open(__file__) as fh:
        tree = ast.parse(fh.read())
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
    assert count_tilings(["..", ".."]) == 2
    assert count_tilings(["...", "..."]) == 3
    assert count_tilings(["....", "....", "....", "...."]) == 36
    # odd number of free cells -> no tiling
    assert count_tilings(["..", ".#"]) == 0
    # single cell board
    assert count_tilings(["."]) == 0
    assert count_tilings([".."]) == 1
    # fully blocked board has exactly one (empty) tiling
    assert count_tilings(["##", "##"]) == 1
    # bad input
    try:
        count_tilings(["..", "."])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for ragged board")
    try:
        count_tilings([".x"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad cell")
    assert stdlib_only()
    print("backtrack_38 OK")


if __name__ == "__main__":
    main()
