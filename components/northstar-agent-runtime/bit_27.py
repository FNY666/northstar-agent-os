"""Subtract without minus (32-bit): a - b via add and two's complement.

Negates b with NOT-plus-one, then reuses the bitwise adder.

What this IS: the subtractor built on the bit_26 adder.
What this IS NOT: unbounded subtraction; it wraps modulo 2**32.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_27_VERSION = "bit-subtract32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-subtract32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def add32(a: int, b: int) -> int:
    """Add mod 2**32 using only bitwise ops."""
    a &= MASK32
    b &= MASK32
    while b:
        carry = (a & b) & MASK32
        a = (a ^ b) & MASK32
        b = (carry << 1) & MASK32
    return a


def to_signed32(n: int) -> int:
    """Interpret a 32-bit word as signed."""
    n &= MASK32
    return n - 0x100000000 if n & 0x80000000 else n


def subtract32(a: int, b: int) -> int:
    """a - b mod 2**32 via add32 and two's complement."""
    return add32(a, add32(~b & MASK32, 1))

def test_sub_basic():
    assert subtract32(10, 3) == 7


def test_sub_negative():
    assert to_signed32(subtract32(3, 10)) == -7


def test_sub_borrow():
    assert subtract32(0, 1) == 0xFFFFFFFF

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
    test_sub_basic()
    test_sub_negative()
    test_sub_borrow()
    assert stdlib_only()
    print("bit-27 OK: subtract32")


if __name__ == "__main__":
    main()
