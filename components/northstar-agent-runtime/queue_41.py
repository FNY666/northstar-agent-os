"""snakes_ladders_min_throws: minimum dice throws to reach the last square on a snakes-and-ladders board via BFS. IS: a minimum throw count; non-square board or bad cells raise ValueError. IS NOT: a DFS or a dynamic-programming solution."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-41.v1"

def _req_board(board: object) -> List[List[int]]:
    if not isinstance(board, list) or not board:
        raise ValueError("board must be a non-empty square list of lists")
    n = len(board)
    for row in board:
        if not isinstance(row, list) or len(row) != n:
            raise ValueError("board must be square")
        for cell in row:
            if isinstance(cell, bool) or not isinstance(cell, int):
                raise ValueError("cells must be ints")
            if cell != -1 and not 1 <= cell <= n * n:
                raise ValueError("snake/ladder targets must be in 1..n*n")
    return board


def _rc(pos: int, n: int):
    q, r = divmod(pos - 1, n)
    row = n - 1 - q
    col = r if q % 2 == 0 else n - 1 - r
    return row, col


def snakes_ladders_min_throws(board: List[List[int]]) -> int:
    """Return the fewest dice throws from square 1 to square n*n."""
    board = _req_board(board)
    n = len(board)
    target = n * n
    if target == 1:
        return 0  # start square is the goal
    q: deque = deque([(1, 0)])
    seen = {1}
    while q:
        pos, throws = q.popleft()
        for nxt in range(pos + 1, min(pos + 6, target) + 1):
            r, c = _rc(nxt, n)
            dest = board[r][c] if board[r][c] != -1 else nxt
            if dest == target:
                return throws + 1
            if dest not in seen:
                seen.add(dest)
                q.append((dest, throws + 1))
    return -1


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    assert snakes_ladders_min_throws([[-1, -1, -1], [-1, -1, -1], [-1, -1, -1]]) == 2
    ladder = [[9, -1, -1], [-1, -1, -1], [-1, -1, -1]]
    assert snakes_ladders_min_throws(ladder) == 1
    assert snakes_ladders_min_throws([[-1]]) == 0
    classic = [[-1, -1, -1, -1, -1, -1], [-1, -1, -1, -1, -1, -1],
               [-1, -1, -1, -1, -1, -1], [-1, 35, -1, -1, 13, -1],
               [-1, -1, -1, -1, -1, -1], [-1, 15, -1, -1, -1, -1]]
    assert snakes_ladders_min_throws(classic) == 4
    try:
        snakes_ladders_min_throws([[-1, -1], [-1]])
    except ValueError:
        pass
    else:
        raise AssertionError("non-square board must raise ValueError")
    try:
        snakes_ladders_min_throws([[0]])
    except ValueError:
        pass
    else:
        raise AssertionError("bad cell value must raise ValueError")
    assert stdlib_only()
    print("queue-41 OK: BFS snakes and ladders")


if __name__ == "__main__":
    main()
