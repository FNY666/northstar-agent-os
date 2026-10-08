"""Lowest set bit: isolate the rightmost 1-bit with n & -n.

Two's complement negation flips trailing zeros to one and the lowest one stays, so AND isolates it.

What this IS: the Fenwick-tree step primitive.
What this IS NOT: an index; it returns the bit value, not its position.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_07_VERSION = "bit-lowest-set-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-lowest-set-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def lowest_set_bit(n: int) -> int:
    """Isolate lowest set bit: n & -n. 0 -> 0."""
    return n & -n

def test_lsb_basic():
    assert lowest_set_bit(12) == 4


def test_lsb_odd():
    assert lowest_set_bit(7) == 1


def test_lsb_zero():
    assert lowest_set_bit(0) == 0


def test_lsb_pow2():
    assert lowest_set_bit(16) == 16

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
    test_lsb_basic()
    test_lsb_odd()
    test_lsb_zero()
    test_lsb_pow2()
    assert stdlib_only()
    print("bit-07 OK: lowest-set-bit")


if __name__ == "__main__":
    main()
