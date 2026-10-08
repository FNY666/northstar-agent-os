"""N-queens backtracking, Simulated.

What this IS: enumerates all N-queens placements via backtracking.

What this IS NOT: not for large N; count grows super-exponentially.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_43_VERSION = "search-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-43.v1"


class SearchError(Exception):
    """Fail-closed."""


def nqueens(n: int) -> List[List[int]]:
    """All solutions; each is a list of column per row."""
    if n < 0:
        raise SearchError("n must be >= 0")
    sols: List[List[int]] = []

    def bt(row: int, cols: set, d1: set, d2: set, board: List[int]) -> None:
        if row == n:
            sols.append(list(board))
            return
        for c in range(n):
            if c in cols or (row - c) in d1 or (row + c) in d2:
                continue
            cols.add(c)
            d1.add(row - c)
            d2.add(row + c)
            board.append(c)
            bt(row + 1, cols, d1, d2, board)
            board.pop()
            cols.discard(c)
            d1.discard(row - c)
            d2.discard(row + c)

    bt(0, set(), set(), set(), [])
    return sols

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
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
    assert len(nqueens(4)) == 2
    assert len(nqueens(1)) == 1
    assert len(nqueens(8)) == 92
    assert stdlib_only()
    print("search-43.v1 OK")


if __name__ == "__main__":
    main()
