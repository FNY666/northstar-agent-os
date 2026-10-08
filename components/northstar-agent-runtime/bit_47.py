"""Swap bytes (16-bit): exchange the two bytes of a half-word.

Masks each byte, shifts them past each other, and ORs them back.

What this IS: the 16-bit endianness swap.
What this IS NOT: a 32-bit bswap; use one call per half-word.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_47_VERSION = "bit-swap-bytes16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-swap-bytes16.v1"


class BitError(Exception):
    """Fail-closed."""


def swap_bytes16(n: int) -> int:
    """Swap the two bytes of a 16-bit value."""
    if not 0 <= n <= 0xFFFF:
        raise BitError("16-bit range required")
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF)

def test_bswap_basic():
    assert swap_bytes16(0x1234) == 0x3412


def test_bswap_low():
    assert swap_bytes16(0x00FF) == 0xFF00


def test_bswap_zero():
    assert swap_bytes16(0) == 0


def test_bswap_range_raises():
    try:
        swap_bytes16(0x10000)
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
    test_bswap_basic()
    test_bswap_low()
    test_bswap_zero()
    test_bswap_range_raises()
    assert stdlib_only()
    print("bit-47 OK: swap-bytes16")


if __name__ == "__main__":
    main()
