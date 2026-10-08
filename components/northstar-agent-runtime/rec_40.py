"""Ackermann (bounded): double recursion with a cap

Bounded to m<=3 to keep it terminating in practice; still pure recursion.

What this IS: a real bounded Ackermann, fail-closed outside the cap.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_40_VERSION = "rec-ackermann.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-ackermann.v1"


class RecError(Exception):
    """Fail-closed."""


def ack(m: int, n: int) -> int:
    """Ackermann, bounded to m <= 3. Fail-closed otherwise."""
    if m < 0 or n < 0:
        raise RecError("ack needs m, n >= 0")
    if m > 3:
        raise RecError("ack bounded to m <= 3")
    if m == 0:
        return n + 1
    if n == 0:
        return ack(m - 1, 1)
    return ack(m - 1, ack(m, n - 1))

def test_ack_m0():
    assert ack(0, 5) == 6


def test_ack_1_1():
    assert ack(1, 1) == 3


def test_ack_2_2():
    assert ack(2, 2) == 7


def test_ack_3_2():
    assert ack(3, 2) == 29


def test_ack_bound_raises():
    try:
        ack(4, 0)
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
    test_ack_m0()
    test_ack_1_1()
    test_ack_2_2()
    test_ack_3_2()
    test_ack_bound_raises()
    assert stdlib_only()
    print("rec-ackermann OK")


if __name__ == "__main__":
    main()
