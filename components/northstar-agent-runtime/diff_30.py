"""Increment Submatrices By One: difference array example.

LeetCode 3212: n x n zero matrix; queries (r1, c1, r2, c2) each add one; return the final matrix via a 2D difference array.

What this IS: the real 2D difference build, fail-closed on bad queries
What this IS NOT: incrementing every cell per query
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_30_VERSION = "increment-submatrices.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-increment-submatrices.v1"


class DiffError(Exception):
    """Fail-closed."""


def increment_submatrices(n: int, queries: list) -> list:
    """Returns the n x n matrix after all +1 submatrix queries."""
    if n <= 0:
        raise DiffError("n must be > 0")
    d = [[0] * (n + 1) for _ in range(n + 1)]
    for r1, c1, r2, c2 in queries:
        if not (0 <= r1 <= r2 < n and 0 <= c1 <= c2 < n):
            raise DiffError("bad query")
        d[r1][c1] += 1
        d[r1][c2 + 1] -= 1
        d[r2 + 1][c1] -= 1
        d[r2 + 1][c2 + 1] += 1
    grid = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            v = d[i][j]
            if i > 0:
                v += grid[i - 1][j]
            if j > 0:
                v += grid[i][j - 1]
            if i > 0 and j > 0:
                v -= grid[i - 1][j - 1]
            grid[i][j] = v
    return grid

def test_example():
    assert increment_submatrices(3, [[0, 0, 1, 1], [2, 2, 2, 2]]) == [[1, 1, 0], [1, 1, 0], [0, 0, 1]]


def test_no_queries():
    assert increment_submatrices(2, []) == [[0, 0], [0, 0]]


def test_full():
    assert increment_submatrices(2, [[0, 0, 1, 1]]) == [[1, 1], [1, 1]]


def test_bad():
    try:
        increment_submatrices(2, [[0, 0, 2, 2]])
    except DiffError:
        return
    raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_example()
    test_no_queries()
    test_full()
    test_bad()
    assert stdlib_only()
    print("diff-30 OK: increment-submatrices")


if __name__ == "__main__":
    main()
