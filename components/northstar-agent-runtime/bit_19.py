"""Swap nibbles (8-bit): exchange the high and low 4 bits of a byte.

Masks each nibble, shifts them past each other, and ORs the result back together.

What this IS: the byte-level shuffle used in nibble codecs.
What this IS NOT: an endianness swap; it works inside one byte.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_19_VERSION = "bit-swap-nibbles8.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-swap-nibbles8.v1"


class BitError(Exception):
    """Fail-closed."""


def swap_nibbles8(n: int) -> int:
    """Swap high/low nibble of a byte."""
    if not 0 <= n <= 0xFF:
        raise BitError("byte range required")
    return ((n & 0x0F) << 4) | ((n & 0xF0) >> 4)

def test_nibble_ab():
    assert swap_nibbles8(0xAB) == 0xBA


def test_nibble_12():
    assert swap_nibbles8(0x12) == 0x21


def test_nibble_zero():
    assert swap_nibbles8(0x00) == 0x00


def test_nibble_range_raises():
    try:
        swap_nibbles8(0x100)
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
    test_nibble_ab()
    test_nibble_12()
    test_nibble_zero()
    test_nibble_range_raises()
    assert stdlib_only()
    print("bit-19 OK: swap-nibbles8")


if __name__ == "__main__":
    main()
