"""Branchless abs (32-bit): absolute value without if-branches.

An arithmetic shift builds an all-ones mask for negatives; XOR-plus-mask flips the sign.

What this IS: the SIMD-style abs used in branchless code.
What this IS NOT: a safe abs for INT_MIN; it wraps like C.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_30_VERSION = "bit-abs-branchless32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-abs-branchless32.v1"


class BitError(Exception):
    """Fail-closed."""


def abs_branchless32(n: int) -> int:
    """abs() for 32-bit signed ints without branching."""
    if not -(2 ** 31) <= n < 2 ** 31:
        raise BitError("32-bit range required")
    mask = n >> 31
    return (n ^ mask) - mask

def test_abs_negative():
    assert abs_branchless32(-5) == 5


def test_abs_positive():
    assert abs_branchless32(5) == 5


def test_abs_zero():
    assert abs_branchless32(0) == 0


def test_abs_range_raises():
    try:
        abs_branchless32(2 ** 31)
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
    test_abs_negative()
    test_abs_positive()
    test_abs_zero()
    test_abs_range_raises()
    assert stdlib_only()
    print("bit-30 OK: abs-branchless32")


if __name__ == "__main__":
    main()
