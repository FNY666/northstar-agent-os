"""Multiply via shift-add: Russian peasant multiplication.

Halves one factor while doubling the other, accumulating the doubled values where the halved factor is odd.

What this IS: the shift-and-add multiplier hardware uses.
What this IS NOT: a general multiply; inputs must be non-negative.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_28_VERSION = "bit-multiply-shift-add.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-multiply-shift-add.v1"


class BitError(Exception):
    """Fail-closed."""


def multiply_shift_add(a: int, b: int) -> int:
    """Russian peasant multiplication for non-negatives."""
    if a < 0 or b < 0:
        raise BitError("non-negative only")
    res = 0
    while b:
        if b & 1:
            res += a
        a <<= 1
        b >>= 1
    return res

def test_mul_basic():
    assert multiply_shift_add(6, 7) == 42


def test_mul_zero():
    assert multiply_shift_add(0, 5) == 0


def test_mul_square():
    assert multiply_shift_add(13, 13) == 169


def test_mul_negative_raises():
    try:
        multiply_shift_add(-2, 3)
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
    test_mul_basic()
    test_mul_zero()
    test_mul_square()
    test_mul_negative_raises()
    assert stdlib_only()
    print("bit-28 OK: multiply-shift-add")


if __name__ == "__main__":
    main()
