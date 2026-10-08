"""Backtracking: 3x3 magic square generator (mock).

IS: enumerates all eight 3x3 normal magic squares (digits 1..9, every
    row, column and both diagonals sum to 15) via backtracking with
    partial-sum pruning. The centre is fixed to 5, which every normal
    3x3 magic square satisfies.
IS NOT: a general n x n magic-square constructor and does not cover
    non-normal or multiplicative magic squares.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

VERSION = "backtrack_37.v1"

MAGIC_SUM = 15
Square = Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]

_LINES = (
    (0, 1, 2), (3, 4, 5), (6, 7, 8),  # rows
    (0, 3, 6), (1, 4, 7), (2, 5, 8),  # cols
    (0, 4, 8), (2, 4, 6),             # diagonals
)


def all_magic_squares() -> List[Square]:
    """Return all 3x3 normal magic squares (row-major, 9 cells)."""
    cells = [0] * 9
    cells[4] = 5  # the centre of a normal 3x3 magic square is always 5
    used = {5}
    out: List[Square] = []

    def line_ok(line) -> bool:
        vals = [cells[i] for i in line]
        filled = [v for v in vals if v]
        if len(filled) == 3:
            return sum(filled) == MAGIC_SUM
        return sum(filled) < MAGIC_SUM

    def bt(pos: int) -> None:
        if pos == 9:
            if all(sum(cells[i] for i in line) == MAGIC_SUM for line in _LINES):
                out.append((tuple(cells[0:3]), tuple(cells[3:6]), tuple(cells[6:9])))
            return
        if cells[pos]:
            bt(pos + 1)
            return
        for d in range(1, 10):
            if d in used:
                continue
            cells[pos] = d
            used.add(d)
            if all(line_ok(line) for line in _LINES if pos in line):
                bt(pos + 1)
            used.discard(d)
            cells[pos] = 0

    bt(0)
    return out


def is_magic(square: Square) -> bool:
    """True when ``square`` is a normal 3x3 magic square."""
    flat = [v for row in square for v in row]
    if sorted(flat) != list(range(1, 10)):
        return False
    cells = flat
    return all(sum(cells[i] for i in line) == MAGIC_SUM for line in _LINES)


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
    squares = all_magic_squares()
    # exactly the 8 rotations/reflections of the Lo Shu square
    assert len(squares) == 8, len(squares)
    assert all(is_magic(s) for s in squares)
    assert len({s for s in squares}) == 8  # all distinct
    # classic Lo Shu is among them
    lo_shu = ((8, 1, 6), (3, 5, 7), (4, 9, 2))
    assert lo_shu in squares
    # every square really uses 1..9 and sums to 15 on all lines
    for s in squares:
        flat = [v for row in s for v in row]
        assert sorted(flat) == list(range(1, 10))
    assert stdlib_only()
    print("backtrack_37 OK")


if __name__ == "__main__":
    main()
