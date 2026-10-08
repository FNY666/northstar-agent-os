"""Backtracking: N-Queens II (count solutions only).

IS: count the number of ways to place n queens on an n x n board with no
two attacking (LeetCode 52). Row-by-row backtracking with column /
diagonal occupancy sets; boards are never materialized, only the count.

IS NOT: N-Queens I - no board layouts are produced or stored; nor the
all-solutions list, nor symmetric-counting tricks. The search is the
plain exhaustive one, so n=8 -> 92 is a real end-to-end run.

Self-test harness: run ``python backtrack_17.py``.
"""

from typing import Set

VERSION = "backtrack_17.v1"

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


def total_n_queens(n: int) -> int:
    """Count distinct n-queen placements (solutions only, no boards)."""
    count = 0
    cols: Set[int] = set()
    diag_down: Set[int] = set()  # row - col
    diag_up: Set[int] = set()  # row + col

    def dfs(row: int) -> None:
        nonlocal count
        if row == n:
            count += 1
            return
        for col in range(n):
            if col in cols or (row - col) in diag_down or (row + col) in diag_up:
                continue
            cols.add(col)
            diag_down.add(row - col)
            diag_up.add(row + col)
            dfs(row + 1)
            cols.discard(col)
            diag_down.discard(row - col)
            diag_up.discard(row + col)

    dfs(0)
    return count


def main() -> None:
    # Canonical count.
    assert total_n_queens(8) == 92
    # Small boards with known counts.
    assert total_n_queens(1) == 1
    assert total_n_queens(4) == 2
    assert total_n_queens(2) == 0
    assert total_n_queens(3) == 0
    assert stdlib_only() is True
    print("backtrack_17 OK")


if __name__ == "__main__":
    main()
