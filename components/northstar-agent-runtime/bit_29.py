"""Divide via bits: floor division by binary long division.

Finds the largest shifted divisor that fits, subtracts it, and records the quotient bit.

What this IS: the restoring-division loop without a divider circuit.
What this IS NOT: a float division; it floors for non-negatives.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_29_VERSION = "bit-divide-bitwise.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-divide-bitwise.v1"


class BitError(Exception):
    """Fail-closed."""


def divide_bitwise(dividend: int, divisor: int) -> int:
    """Floor division for non-negatives via bit long-division."""
    if divisor == 0:
        raise BitError("division by zero")
    if dividend < 0 or divisor < 0:
        raise BitError("non-negative only")
    q = 0
    while dividend >= divisor:
        shift = 0
        while dividend >= (divisor << (shift + 1)):
            shift += 1
        dividend -= divisor << shift
        q += 1 << shift
    return q

def test_div_basic():
    assert divide_bitwise(10, 3) == 3


def test_div_exact():
    assert divide_bitwise(7, 1) == 7


def test_div_zero_dividend():
    assert divide_bitwise(0, 5) == 0


def test_div_smaller():
    assert divide_bitwise(5, 10) == 0


def test_div_by_zero_raises():
    try:
        divide_bitwise(5, 0)
    except BitError:
        return
    raise AssertionError("expected BitError")

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
    test_div_basic()
    test_div_exact()
    test_div_zero_dividend()
    test_div_smaller()
    test_div_by_zero_raises()
    assert stdlib_only()
    print("bit-29 OK: divide-bitwise")


if __name__ == "__main__":
    main()
