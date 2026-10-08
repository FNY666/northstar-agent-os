"""Rotate right (32-bit): circular right shift of a 32-bit word.

Bits shifted out on the right are ORed back in on the left; the mask keeps 32 bits.

What this IS: the inverse of rotate-left used in block ciphers.
What this IS NOT: an arithmetic shift; sign is not extended.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_23_VERSION = "bit-rotate-right32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-rotate-right32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def rotate_right32(n: int, k: int) -> int:
    """Circular right shift of a 32-bit word by k."""
    n &= MASK32
    k %= 32
    return ((n >> k) | (n << (32 - k))) & MASK32

def test_rotr_basic():
    assert rotate_right32(0x12345678, 4) == 0x81234567


def test_rotr_one():
    assert rotate_right32(1, 1) == 0x80000000


def test_rotr_roundtrip():
    assert rotate_right32(rotate_right32(0xDEADBEEF, 13), 32 - 13) == 0xDEADBEEF

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
    test_rotr_basic()
    test_rotr_one()
    test_rotr_roundtrip()
    assert stdlib_only()
    print("bit-23 OK: rotate-right32")


if __name__ == "__main__":
    main()
