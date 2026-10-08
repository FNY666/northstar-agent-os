"""Fill below MSB: set every bit below the top 1-bit.

Each OR-shift doubles the run of ones downward until the whole field below the MSB is set.

What this IS: the mask builder behind next-power-of-two.
What this IS NOT: a rounding function; it returns a mask, not a power.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_18_VERSION = "bit-fill-below-msb.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-fill-below-msb.v1"


class BitError(Exception):
    """Fail-closed."""


def fill_below_msb(n: int) -> int:
    """Smear the top set bit downward: all bits below MSB become 1."""
    if n <= 0:
        raise BitError("n > 0 required")
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    n |= n >> 32
    return n

def test_fill_basic():
    assert fill_below_msb(12) == 15


def test_fill_pow2():
    assert fill_below_msb(16) == 31


def test_fill_one():
    assert fill_below_msb(1) == 1


def test_fill_zero_raises():
    try:
        fill_below_msb(0)
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
    test_fill_basic()
    test_fill_pow2()
    test_fill_one()
    test_fill_zero_raises()
    assert stdlib_only()
    print("bit-18 OK: fill-below-msb")


if __name__ == "__main__":
    main()
