"""Add without plus (32-bit): addition via XOR and carry shifts.

XOR sums without carry; AND-shift computes the carry; repeat until no carry remains.

What this IS: the ALU-style adder every software carry chain mimics.
What this IS NOT: unbounded addition; it wraps modulo 2**32.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_26_VERSION = "bit-add32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-add32.v1"


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

def test_add_basic():
    assert add32(5, 7) == 12


def test_add_wrap():
    assert add32(0xFFFFFFFF, 1) == 0


def test_add_negative():
    assert to_signed32(add32(0xFFFFFFFB, 7)) == 2  # -5 + 7


def test_to_signed():
    assert to_signed32(0xFFFFFFFF) == -1

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
    test_add_basic()
    test_add_wrap()
    test_add_negative()
    test_to_signed()
    assert stdlib_only()
    print("bit-26 OK: add32")


if __name__ == "__main__":
    main()
