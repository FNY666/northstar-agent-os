"""Backtracking: knight's tour on 5x5 (find one tour).

IS: find a single open knight's tour on the 5x5 board starting from the
(0,0) corner - a sequence of 25 knight moves visiting every square
exactly once. Plain depth-first backtracking, ordered by Warnsdorff's
heuristic (fewest onward moves first), which keeps the 5x5 search fast.

IS NOT: enumerating all tours, finding a *closed* tour (impossible on
an odd board), or proving optimality - it returns the first complete
tour the heuristic-guided search finds.

Self-test harness: run ``python backtrack_18.py``.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

VERSION = "backtrack_18.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


KNIGHT_MOVES: Tuple[Tuple[int, int], ...] = (
    (2, 1), (1, 2), (-1, 2), (-2, 1),
    (-2, -1), (-1, -2), (1, -2), (2, -1),
)


@dataclass(frozen=True)
class Tour:
    """A completed knight's tour: board[r][c] is the move index."""
    size: int
    board: Tuple[Tuple[int, ...], ...]

    def positions(self) -> List[Tuple[int, int]]:
        order: List[Tuple[int, int]] = [(0, 0)] * (self.size * self.size)
        for r in range(self.size):
            for c in range(self.size):
                order[self.board[r][c]] = (r, c)
        return order


def knights_tour(size: int = 5, start: Tuple[int, int] = (0, 0)) -> Optional[Tour]:
    """Find one open knight's tour on a size x size board, or None."""
    board: List[List[int]] = [[-1] * size for _ in range(size)]
    sx, sy = start
    board[sx][sy] = 0

    def onward_moves(x: int, y: int) -> int:
        n = 0
        for dx, dy in KNIGHT_MOVES:
            nx, ny = x + dx, y + dy
            if 0 <= nx < size and 0 <= ny < size and board[nx][ny] == -1:
                n += 1
        return n

    def dfs(x: int, y: int, move: int) -> bool:
        if move == size * size:
            return True
        ranked = []
        for dx, dy in KNIGHT_MOVES:
            nx, ny = x + dx, y + dy
            if 0 <= nx < size and 0 <= ny < size and board[nx][ny] == -1:
                ranked.append((onward_moves(nx, ny), nx, ny))
        ranked.sort()  # Warnsdorff: fewest onward moves first
        for _, nx, ny in ranked:
            board[nx][ny] = move
            if dfs(nx, ny, move + 1):
                return True
            board[nx][ny] = -1
        return False

    if dfs(sx, sy, 1):
        return Tour(size=size, board=tuple(tuple(row) for row in board))
    return None


def main() -> None:
    tour = knights_tour(5)
    # A tour is found.
    assert tour is not None
    # Every square visited exactly once (moves 0..24).
    seen = sorted(v for row in tour.board for v in row)
    assert seen == list(range(25)), seen
    # Starts at the requested corner.
    assert tour.board[0][0] == 0
    # Every consecutive pair is a legal knight move.
    order = tour.positions()
    for (r1, c1), (r2, c2) in zip(order, order[1:]):
        assert (abs(r1 - r2), abs(c1 - c2)) in ((1, 2), (2, 1)), (
            (r1, c1), (r2, c2))
    # 1x1 board: the trivial tour.
    tiny = knights_tour(1)
    assert tiny is not None and tiny.board == ((0,),)
    assert stdlib_only() is True
    print("backtrack_18 OK")


if __name__ == "__main__":
    main()
