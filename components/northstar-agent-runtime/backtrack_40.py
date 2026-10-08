"""Backtracking: pentomino placement checker (mock).

IS: lists every placement (position x orientation) of a single given
    pentomino on a small board's free cells, enumerating all unique
    rotations/reflections of the piece.
IS NOT: a pentomino tiling solver; it never attempts multi-piece packing.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, List, Set, Tuple

VERSION = "backtrack_40.v1"

Cell = Tuple[int, int]

PENTOMINOES: dict = {
    "F": frozenset({(0, 1), (1, 0), (1, 1), (1, 2), (2, 0)}),
    "I": frozenset({(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)}),
    "L": frozenset({(0, 0), (1, 0), (2, 0), (3, 0), (3, 1)}),
    "N": frozenset({(0, 1), (0, 2), (1, 0), (1, 1), (2, 0)}),
    "P": frozenset({(0, 0), (0, 1), (1, 0), (1, 1), (2, 0)}),
    "T": frozenset({(0, 0), (0, 1), (0, 2), (1, 1), (2, 1)}),
    "U": frozenset({(0, 0), (0, 2), (1, 0), (1, 1), (1, 2)}),
    "V": frozenset({(0, 0), (1, 0), (2, 0), (2, 1), (2, 2)}),
    "W": frozenset({(0, 0), (1, 0), (1, 1), (2, 1), (2, 2)}),
    "X": frozenset({(0, 1), (1, 0), (1, 1), (1, 2), (2, 1)}),
    "Y": frozenset({(0, 1), (1, 0), (1, 1), (2, 1), (3, 1)}),
    "Z": frozenset({(0, 0), (0, 1), (1, 1), (2, 1), (2, 2)}),
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


def placements(board: List[str], name: str) -> List[FrozenSet[Cell]]:
    """Every placement of pentomino ``name`` fitting the free ('.') cells."""
    if name not in PENTOMINOES:
        raise ValueError("unknown pentomino %r" % name)
    if not board:
        raise ValueError("board must be non-empty")
    rows, cols = len(board), len(board[0])
    if any(len(row) != cols for row in board):
        raise ValueError("board rows must all have the same length")
    free = {(r, c) for r in range(rows) for c in range(cols) if board[r][c] == "."}

    out: List[FrozenSet[Cell]] = []
    for shape in _orientations(PENTOMINOES[name]):
        h = max(r for r, _ in shape) + 1
        w = max(c for _, c in shape) + 1
        for dr in range(rows - h + 1):
            for dc in range(cols - w + 1):
                placed = frozenset((r + dr, c + dc) for r, c in shape)
                if placed <= free:
                    out.append(placed)
    return out


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
    board3 = ["...", "...", "..."]
    # X pentomino fits a 3x3 board in exactly one way (centred)
    x_places = placements(board3, "X")
    assert len(x_places) == 1, x_places
    assert x_places[0] == frozenset({(0, 1), (1, 0), (1, 1), (1, 2), (2, 1)})
    # block the centre -> X fits nowhere
    assert placements(["...", ".#.", "..."], "X") == []
    # I pentomino on empty 5x5: 5 horizontal + 5 vertical
    assert len(placements(["....."] * 5, "I")) == 10
    # every placement stays inside the free cells
    for p in placements(["....", "...."], "P"):
        assert all(0 <= r < 2 and 0 <= c < 4 for r, c in p) and len(p) == 5
    assert len(placements(["....", "...."], "P")) >= 1
    # unknown pentomino -> ValueError
    try:
        placements(board3, "Q")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown pentomino")
    assert stdlib_only()
    print("backtrack_40 OK")


if __name__ == "__main__":
    main()
