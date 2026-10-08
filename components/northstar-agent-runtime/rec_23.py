"""Digit count: 1 + count(n // 10)

0 counts as one digit; each call drops a decimal digit.

What this IS: a real recursive digit counter, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_23_VERSION = "rec-count-digits.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-count-digits.v1"


class RecError(Exception):
    """Fail-closed."""


def count_digits(n: int) -> int:
    """Decimal digit count. Fail-closed on negatives."""
    if n < 0:
        raise RecError("count_digits needs n >= 0")
    if n < 10:
        return 1
    return 1 + count_digits(n // 10)

def test_count_digits_basic():
    assert count_digits(12345) == 5


def test_count_digits_zero():
    assert count_digits(0) == 1


def test_count_digits_single():
    assert count_digits(7) == 1


def test_count_digits_negative_raises():
    try:
        count_digits(-3)
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
    test_count_digits_basic()
    test_count_digits_zero()
    test_count_digits_single()
    test_count_digits_negative_raises()
    assert stdlib_only()
    print("rec-count-digits OK")


if __name__ == "__main__":
    main()
