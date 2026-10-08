"""Backtracking: N-Queens solver.

Finds all valid placements of n queens on an n x n chessboard such that no
two queens attack each other (same row, column, or diagonal).

IS: classic backtracking with column/diagonal pruning; returns all solutions.
IS NOT: a counting-only solver; NOT a general constraint solver.
"""

from typing import List
import ast

VERSION = "backtrack_01.v1"


def solve_n_queens(n: int) -> List[List[int]]:
    """Return all solutions; each solution is a list of column indices per row."""
    solutions: List[List[int]] = []
    cols: List[int] = []

    def safe(row: int, col: int) -> bool:
        for r, c in enumerate(cols):
            if c == col or abs(c - col) == abs(r - row):
                return False
        return True

    def backtrack(row: int) -> None:
        if row == n:
            solutions.append(list(cols))
            return
        for col in range(n):
            if safe(row, col):
                cols.append(col)
                backtrack(row + 1)
                cols.pop()

    backtrack(0)
    return solutions


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
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
    s4 = solve_n_queens(4)
    assert len(s4) == 2, s4
    s1 = solve_n_queens(1)
    assert s1 == [[0]], s1
    s8 = solve_n_queens(8)
    assert len(s8) == 92, len(s8)
    assert stdlib_only()
    print("backtrack_01 OK")


if __name__ == "__main__":
    main()
