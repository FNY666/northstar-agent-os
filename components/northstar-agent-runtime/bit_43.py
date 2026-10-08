"""Number complement: flip every bit up to the MSB.

A mask of ones spanning the bit-length XORs each significant bit exactly once.

What this IS: the bounded complement (leading zeros stay zero).
What this IS NOT: a bitwise NOT; width is the value's own length.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_43_VERSION = "bit-number-complement.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-number-complement.v1"


class BitError(Exception):
    """Fail-closed."""


def number_complement(n: int) -> int:
    """Flip bits up to MSB."""
    if n <= 0:
        raise BitError("n > 0 required")
    mask = (1 << n.bit_length()) - 1
    return mask ^ n

def test_comp_basic():
    assert number_complement(5) == 2  # 101 -> 010


def test_comp_one():
    assert number_complement(1) == 0


def test_comp_pow2():
    assert number_complement(8) == 7  # 1000 -> 0111


def test_comp_zero_raises():
    try:
        number_complement(0)
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
    test_comp_basic()
    test_comp_one()
    test_comp_pow2()
    test_comp_zero_raises()
    assert stdlib_only()
    print("bit-43 OK: number-complement")


if __name__ == "__main__":
    main()
