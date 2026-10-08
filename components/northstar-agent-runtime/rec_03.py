"""Tower of Hanoi: move list by recursion

Move n-1 disks to aux, move the largest, then move n-1 from aux to dst: 2^n - 1 moves.

What this IS: a real recursive Hanoi solver returning the move list.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_03_VERSION = "rec-hanoi.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-hanoi.v1"


class RecError(Exception):
    """Fail-closed."""


def hanoi(n: int, src="A", dst="C", aux="B"):
    """List of (from, to) moves. Fail-closed on negatives."""
    if n < 0:
        raise RecError("hanoi needs n >= 0")
    if n == 0:
        return []
    return hanoi(n - 1, src, aux, dst) + [(src, dst)] + hanoi(n - 1, aux, dst, src)

def test_hanoi_zero():
    assert hanoi(0) == []


def test_hanoi_one():
    assert hanoi(1) == [("A", "C")]


def test_hanoi_three_count():
    assert len(hanoi(3)) == 7


def test_hanoi_negative_raises():
    try:
        hanoi(-1)
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
    test_hanoi_zero()
    test_hanoi_one()
    test_hanoi_three_count()
    test_hanoi_negative_raises()
    assert stdlib_only()
    print("rec-hanoi OK")


if __name__ == "__main__":
    main()
