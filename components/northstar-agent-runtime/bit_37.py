"""Count leading zeros (32-bit): number of high zero bits.

Thirty-two minus the bit-length is exactly the count of leading zeros.

What this IS: the clz behind normalization and log2 estimates.
What this IS NOT: a width detector; width is pinned to 32.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_37_VERSION = "bit-count-leading-zeros32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-count-leading-zeros32.v1"


class BitError(Exception):
    """Fail-closed."""


def count_leading_zeros32(n: int) -> int:
    """Count high zero bits of a 32-bit word; 0 -> 32."""
    return 32 - (n & 0xFFFFFFFF).bit_length()

def test_clz_basic():
    assert count_leading_zeros32(1) == 31


def test_clz_high():
    assert count_leading_zeros32(0x80000000) == 0


def test_clz_zero():
    assert count_leading_zeros32(0) == 32


def test_clz_byte():
    assert count_leading_zeros32(0xFF) == 24

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
    test_clz_basic()
    test_clz_high()
    test_clz_zero()
    test_clz_byte()
    assert stdlib_only()
    print("bit-37 OK: count-leading-zeros32")


if __name__ == "__main__":
    main()
