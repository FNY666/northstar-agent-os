"""Highest set bit: largest power of two not exceeding n.

bit_length gives the position of the top 1-bit; shifting 1 there rebuilds its value.

What this IS: the floor-log2 building block for sizing tables.
What this IS NOT: a logarithm function; it returns a bit value.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_08_VERSION = "bit-highest-set-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-highest-set-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def highest_set_bit(n: int) -> int:
    """Largest power of two <= n. 0 -> 0; negatives fail closed."""
    if n < 0:
        raise BitError("negative")
    if n == 0:
        return 0
    return 1 << (n.bit_length() - 1)

def test_hsb_basic():
    assert highest_set_bit(12) == 8


def test_hsb_exact():
    assert highest_set_bit(16) == 16


def test_hsb_zero():
    assert highest_set_bit(0) == 0


def test_hsb_negative_raises():
    try:
        highest_set_bit(-3)
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
    test_hsb_basic()
    test_hsb_exact()
    test_hsb_zero()
    test_hsb_negative_raises()
    assert stdlib_only()
    print("bit-08 OK: highest-set-bit")


if __name__ == "__main__":
    main()
