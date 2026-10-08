"""Count trailing zeros (32-bit): number of low zero bits.

Isolating the lowest set bit turns the count into a bit-length question.

What this IS: the ctz used by alignment and factor-2 extraction.
What this IS NOT: a log; it counts zeros, not value magnitude.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_36_VERSION = "bit-count-trailing-zeros32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-count-trailing-zeros32.v1"


class BitError(Exception):
    """Fail-closed."""


def count_trailing_zeros32(n: int) -> int:
    """Count low zero bits of a 32-bit word; 0 -> 32."""
    n &= 0xFFFFFFFF
    if n == 0:
        return 32
    return (n & -n).bit_length() - 1

def test_ctz_basic():
    assert count_trailing_zeros32(12) == 2  # 1100


def test_ctz_pow2():
    assert count_trailing_zeros32(8) == 3


def test_ctz_one():
    assert count_trailing_zeros32(1) == 0


def test_ctz_zero():
    assert count_trailing_zeros32(0) == 32

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
    test_ctz_basic()
    test_ctz_pow2()
    test_ctz_one()
    test_ctz_zero()
    assert stdlib_only()
    print("bit-36 OK: count-trailing-zeros32")


if __name__ == "__main__":
    main()
