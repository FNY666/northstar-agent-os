"""Two's complement negation: negate a 32-bit word with NOT-plus-one.

Flipping every bit and adding one is the definition of two's complement negation.

What this IS: the negator the bit_27 subtractor relies on.
What this IS NOT: a Python unary minus; it wraps modulo 2**32.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_35_VERSION = "bit-negate32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-negate32.v1"


class BitError(Exception):
    """Fail-closed."""


MASK32 = 0xFFFFFFFF


def negate32(n: int) -> int:
    """Two's complement negation mod 2**32."""
    return (~(n & MASK32) + 1) & MASK32

def test_neg_basic():
    assert negate32(5) == 0xFFFFFFFB


def test_neg_zero():
    assert negate32(0) == 0


def test_neg_all_ones():
    assert negate32(0xFFFFFFFF) == 1


def test_neg_twice():
    assert negate32(negate32(123456)) == 123456

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
    test_neg_basic()
    test_neg_zero()
    test_neg_all_ones()
    test_neg_twice()
    assert stdlib_only()
    print("bit-35 OK: negate32")


if __name__ == "__main__":
    main()
