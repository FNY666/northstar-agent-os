"""Rotate left (32-bit): circular left shift of a 32-bit word.

Bits shifted out on the left are ORed back in on the right; the mask keeps 32 bits.

What this IS: the rotation primitive behind hash mixing.
What this IS NOT: a logical shift; no bit is lost.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_22_VERSION = "bit-rotate-left32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-rotate-left32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def rotate_left32(n: int, k: int) -> int:
    """Circular left shift of a 32-bit word by k."""
    n &= MASK32
    k %= 32
    return ((n << k) | (n >> (32 - k))) & MASK32

def test_rotl_basic():
    assert rotate_left32(0x12345678, 4) == 0x23456781


def test_rotl_one():
    assert rotate_left32(1, 1) == 2


def test_rotl_wrap():
    assert rotate_left32(0x80000000, 1) == 1


def test_rotl_zero():
    assert rotate_left32(0x12345678, 0) == 0x12345678

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
    test_rotl_basic()
    test_rotl_one()
    test_rotl_wrap()
    test_rotl_zero()
    assert stdlib_only()
    print("bit-22 OK: rotate-left32")


if __name__ == "__main__":
    main()
