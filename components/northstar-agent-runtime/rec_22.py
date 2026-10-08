"""Digit sum: last digit + sum(rest)

Splits off n % 10 each call; depth is O(digits).

What this IS: a real recursive digit sum, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_22_VERSION = "rec-digit-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-digit-sum.v1"


class RecError(Exception):
    """Fail-closed."""


def digit_sum(n: int) -> int:
    """Sum of decimal digits. Fail-closed on negatives."""
    if n < 0:
        raise RecError("digit_sum needs n >= 0")
    if n < 10:
        return n
    return n % 10 + digit_sum(n // 10)

def test_digit_sum_basic():
    assert digit_sum(12345) == 15


def test_digit_sum_zero():
    assert digit_sum(0) == 0


def test_digit_sum_single():
    assert digit_sum(9) == 9


def test_digit_sum_negative_raises():
    try:
        digit_sum(-5)
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
    test_digit_sum_basic()
    test_digit_sum_zero()
    test_digit_sum_single()
    test_digit_sum_negative_raises()
    assert stdlib_only()
    print("rec-digit-sum OK")


if __name__ == "__main__":
    main()
