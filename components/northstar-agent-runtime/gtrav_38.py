"""Knight's shortest moves via BFS. IS: fewest knight moves between squares on an n-by-n board. IS NOT: a tour finder."""

from __future__ import annotations

import ast

VERSION = "gtrav-38.v1"

def _req_board(n: object) -> int:
    if not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    return n


def _req_square(n: int, sq: object, name: str) -> tuple:
    if not isinstance(sq, (list, tuple)) or len(sq) != 2:
        raise ValueError(name + " must be a (row, col) pair")
    r, c = sq[0], sq[1]
    if not isinstance(r, int) or not isinstance(c, int):
        raise ValueError(name + " coordinates must be ints")
    if not (0 <= r < n and 0 <= c < n):
        raise ValueError(name + " is off the board")
    return (r, c)


_KNIGHT = [(2, 1), (1, 2), (-1, 2), (-2, 1), (-2, -1), (-1, -2), (1, -2), (2, -1)]


def bfs_knight(n: object, start: object, target: object) -> object:
    """Return fewest knight moves from start to target, or None."""
    n = _req_board(n)
    sr, sc = _req_square(n, start, "start")
    tr, tc = _req_square(n, target, "target")
    if (sr, sc) == (tr, tc):
        return 0
    seen: set = {(sr, sc)}
    queue: list = [((sr, sc), 0)]
    while queue:
        (r, c), d = queue.pop(0)
        for dr, dc in _KNIGHT:
            nr, nc = r + dr, c + dc
            if 0 <= nr < n and 0 <= nc < n and (nr, nc) not in seen:
                if (nr, nc) == (tr, tc):
                    return d + 1
                seen.add((nr, nc))
                queue.append(((nr, nc), d + 1))
    return None


def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert bfs_knight(5, (0, 0), (1, 2)) == 1
    assert bfs_knight(5, (0, 0), (0, 0)) == 0
    assert bfs_knight(8, (0, 0), (7, 7)) == 6
    assert bfs_knight(2, (0, 0), (1, 1)) is None
    try:
        bfs_knight(8, (0, 0), (8, 8))
    except ValueError:
        pass
    else:
        raise AssertionError("off-board target must raise ValueError")
    try:
        bfs_knight(0, (0, 0), (0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    assert stdlib_only()
    print("gtrav_38 OK")


if __name__ == "__main__":
    main()
