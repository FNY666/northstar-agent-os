"""Backtracking: Minesweeper board consistency check (mock).

IS: decides whether a partially revealed small board admits at least one
    mine placement consistent with every revealed number, via exhaustive
    backtracking with forward checking. Counts consistent assignments.
IS NOT: a Minesweeper solver/AI, a mine-probability engine, or a
    large-board constraint solver.
"""

from __future__ import annotations

import ast
from typing import List, Set, Tuple

VERSION = "backtrack_33.v1"

Cell = Tuple[int, int]


def _neighbours(r: int, c: int, rows: int, cols: int):
    for dr in (-1, 0, 1):
        for dc in (-1, 0, 1):
            if dr == 0 and dc == 0:
                continue
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                yield nr, nc


def count_consistent(board: List[str]) -> int:
    """Count mine assignments consistent with all revealed numbers.

    Board chars: '0'-'8' revealed, '?' covered, '*' known mine.
    """
    if not board:
        raise ValueError("board must be non-empty")
    rows, cols = len(board), len(board[0])
    if any(len(row) != cols for row in board):
        raise ValueError("board rows must all have the same length")

    unknowns: List[Cell] = []
    known_mines: Set[Cell] = set()
    numbered: List[Tuple[int, int, int]] = []
    for r in range(rows):
        for c in range(cols):
            ch = board[r][c]
            if ch == "?":
                unknowns.append((r, c))
            elif ch == "*":
                known_mines.add((r, c))
            elif ch.isdigit():
                numbered.append((r, c, int(ch)))
            else:
                raise ValueError("bad cell %r at %r" % (ch, (r, c)))

    # Per-number constraint: (unknown neighbour cells, mines still needed)
    constraints: List[Tuple[List[Cell], int]] = []
    for r, c, n in numbered:
        unk: List[Cell] = []
        known = 0
        for nr, nc in _neighbours(r, c, rows, cols):
            if (nr, nc) in known_mines:
                known += 1
            elif board[nr][nc] == "?":
                unk.append((nr, nc))
        target = n - known
        if target < 0 or target > len(unk):
            return 0
        constraints.append((unk, target))

    assign: dict = {}

    def feasible() -> bool:
        for unk, target in constraints:
            low = 0
            unassigned = 0
            for cell in unk:
                if cell in assign:
                    if assign[cell]:
                        low += 1
                else:
                    unassigned += 1
            if not (low <= target <= low + unassigned):
                return False
        return True

    count = 0

    def bt(i: int) -> None:
        nonlocal count
        if i == len(unknowns):
            count += 1
            return
        cell = unknowns[i]
        for val in (False, True):
            assign[cell] = val
            if feasible():
                bt(i + 1)
            del assign[cell]

    bt(0)
    return count


def is_consistent(board: List[str]) -> bool:
    """True when at least one consistent mine placement exists."""
    return count_consistent(board) > 0


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
    # corner '1' with 3 covered neighbours -> exactly 3 assignments
    assert count_consistent(["1?", "??"]) == 3
    assert is_consistent(["1?", "??"])
    # '0' forces empties, '1' needs a mine there -> contradiction
    assert count_consistent(["01", "??"]) == 0
    assert not is_consistent(["01", "??"])
    # flagged mine satisfies the '1' outright -> unique assignment
    assert count_consistent(["1*", "??"]) == 1
    # empty board (no numbers) -> all 2^n assignments
    assert count_consistent(["??", "??"]) == 16
    # invalid char
    try:
        count_consistent(["1x", "??"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad cell")
    assert stdlib_only()
    print("backtrack_33 OK")


if __name__ == "__main__":
    main()
