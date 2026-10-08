"""N-Queens count: place row by row with conflict sets

Tracks used columns and both diagonals; counts full placements.

What this IS: a real recursive N-Queens counter, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_19_VERSION = "rec-nqueens.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-nqueens.v1"


class RecError(Exception):
    """Fail-closed."""


def nqueens(n: int) -> int:
    """Number of n-queens placements. Fail-closed on negatives."""
    if n < 0:
        raise RecError("nqueens needs n >= 0")

    def place(row, cols, d1, d2) -> int:
        if row == n:
            return 1
        total = 0
        for c in range(n):
            if c in cols or (row - c) in d1 or (row + c) in d2:
                continue
            total += place(row + 1, cols | {c}, d1 | {row - c}, d2 | {row + c})
        return total

    return place(0, set(), set(), set())

def test_nqueens_one():
    assert nqueens(1) == 1


def test_nqueens_four():
    assert nqueens(4) == 2


def test_nqueens_eight():
    assert nqueens(8) == 92


def test_nqueens_negative_raises():
    try:
        nqueens(-1)
    except RecError:
        return
    raise AssertionError("expected RecError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_nqueens_one()
    test_nqueens_four()
    test_nqueens_eight()
    test_nqueens_negative_raises()
    assert stdlib_only()
    print("rec-nqueens OK")


if __name__ == "__main__":
    main()
