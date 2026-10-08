"""Backtracking: tetromino exact-cover tiler (mock).

IS: counts ways to tile a small board's free cells with a given multiset
    of tetromino pieces (all rotations/reflections generated, each piece
    used at most once) via exact-cover backtracking.
IS NOT: a full pentomino/polyomino solver, a DLX implementation, or a
    large-board exact-cover engine.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, List, Set, Tuple

VERSION = "backtrack_39.v1"

Cell = Tuple[int, int]

TETROMINOES: dict = {
    "I": frozenset({(0, 0), (0, 1), (0, 2), (0, 3)}),
    "O": frozenset({(0, 0), (0, 1), (1, 0), (1, 1)}),
    "T": frozenset({(0, 0), (0, 1), (0, 2), (1, 1)}),
    "S": frozenset({(0, 1), (0, 2), (1, 0), (1, 1)}),
    "Z": frozenset({(0, 0), (0, 1), (1, 1), (1, 2)}),
    "J": frozenset({(0, 0), (1, 0), (1, 1), (1, 2)}),
    "L": frozenset({(0, 2), (1, 0), (1, 1), (1, 2)}),
}


def _orientations(cells: FrozenSet[Cell]) -> Set[FrozenSet[Cell]]:
    """All unique rotations/reflections of a cell set, normalised."""
    seen: Set[FrozenSet[Cell]] = set()
    pts = list(cells)
    for _ in range(2):  # original + reflected
        for _ in range(4):  # 4 rotations
            mr = min(r for r, _ in pts)
            mc = min(c for _, c in pts)
            seen.add(frozenset((r - mr, c - mc) for r, c in pts))
            pts = [(-c, r) for r, c in pts]
        pts = [(r, -c) for r, c in pts]
    return seen


def tile_count(board: List[str], pieces: List[str]) -> int:
    """Count exact tilings of the free cells using each piece at most once.

    ``board``: '.' free, '#' blocked. ``pieces``: tetromino names from
    :data:`TETROMINOES`. Identical pieces are treated as indistinguishable.
    """
    if not board:
        raise ValueError("board must be non-empty")
    rows, cols = len(board), len(board[0])
    if any(len(row) != cols for row in board):
        raise ValueError("board rows must all have the same length")
    for name in pieces:
        if name not in TETROMINOES:
            raise ValueError("unknown tetromino %r" % name)

    free = {(r, c) for r in range(rows) for c in range(cols) if board[r][c] == "."}
    if len(free) != 4 * len(pieces):
        return 0

    oris = {name: _orientations(TETROMINOES[name]) for name in set(pieces)}
    used = [False] * len(pieces)
    covered: Set[Cell] = set()
    count = 0

    def bt() -> None:
        nonlocal count
        if len(covered) == len(free):
            count += 1
            return
        cell = min(free - covered)
        r0, c0 = cell
        seen_names: Set[str] = set()
        for i, name in enumerate(pieces):
            if used[i] or name in seen_names:
                continue
            seen_names.add(name)
            for shape in oris[name]:
                for sr, sc in shape:
                    dr, dc = r0 - sr, c0 - sc
                    placed = frozenset((r + dr, c + dc) for r, c in shape)
                    if placed <= free and not (placed & covered):
                        used[i] = True
                        covered.update(placed)
                        bt()
                        used[i] = False
                        covered.difference_update(placed)

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
    # 2x4 board with two O tetrominoes -> exactly one tiling
    assert tile_count(["....", "...."], ["O", "O"]) == 1
    # 1x4 with one I -> horizontal only
    assert tile_count(["...."], ["I"]) == 1
    # 4x4 with four I tetrominoes: only 2 tilings (all rows horizontal, or
    # all columns vertical; any mixed layout is impossible since a
    # horizontal I occupies a whole row and blocks every vertical one)
    assert tile_count(["....", "....", "....", "...."], ["I"] * 4) == 2
    # two T's cannot tile a 2x4 board
    assert tile_count(["....", "...."], ["T", "T"]) == 0
    # wrong cell count -> 0
    assert tile_count(["....", "...."], ["O"]) == 0
    # unknown piece -> ValueError
    try:
        tile_count(["...."], ["Q"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown tetromino")
    assert stdlib_only()
    print("backtrack_39 OK")


if __name__ == "__main__":
    main()
