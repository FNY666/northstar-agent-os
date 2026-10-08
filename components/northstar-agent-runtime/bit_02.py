"""Reverse bits (32-bit): mirror the bit order of a 32-bit word.

Shifts the input right while building the output left, one bit per step, for exactly 32 steps.

What this IS: an exact 32-bit reversal used in FFT-style bit shuffles.
What this IS NOT: a variable-width reversal; width is pinned to 32.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_02_VERSION = "bit-reverse-bits32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-reverse-bits32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def reverse_bits32(n: int) -> int:
    """Reverse the bits of a 32-bit unsigned integer."""
    n &= MASK32
    rev = 0
    for _ in range(32):
        rev = (rev << 1) | (n & 1)
        n >>= 1
    return rev

def test_reverse_single_bit():
    assert reverse_bits32(1) == 0x80000000


def test_reverse_high_bit():
    assert reverse_bits32(0x80000000) == 1


def test_reverse_all_ones():
    assert reverse_bits32(0xFFFFFFFF) == 0xFFFFFFFF


def test_reverse_roundtrip():
    assert reverse_bits32(reverse_bits32(0x12345678)) == 0x12345678

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
    test_reverse_single_bit()
    test_reverse_high_bit()
    test_reverse_all_ones()
    test_reverse_roundtrip()
    assert stdlib_only()
    print("bit-02 OK: reverse-bits32")


if __name__ == "__main__":
    main()
