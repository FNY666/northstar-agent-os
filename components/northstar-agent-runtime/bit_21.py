"""Swap adjacent bits (32-bit): exchange every even/odd bit pair.

Even and odd positions are masked apart, shifted toward each other, and recombined.

What this IS: the pairwise permutation behind some interleave codecs.
What this IS NOT: a reversal; order of pairs is preserved.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_21_VERSION = "bit-swap-adjacent32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-swap-adjacent32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def swap_adjacent32(n: int) -> int:
    """Swap every pair of adjacent bits (32-bit)."""
    n &= MASK32
    return (((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1)) & MASK32

def test_adj_basic():
    assert swap_adjacent32(0b10) == 0b01


def test_adj_nibble():
    assert swap_adjacent32(0b1010) == 0b0101


def test_adj_all_ones():
    assert swap_adjacent32(0xFFFFFFFF) == 0xFFFFFFFF


def test_adj_zero():
    assert swap_adjacent32(0) == 0

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
    test_adj_basic()
    test_adj_nibble()
    test_adj_all_ones()
    test_adj_zero()
    assert stdlib_only()
    print("bit-21 OK: swap-adjacent32")


if __name__ == "__main__":
    main()
