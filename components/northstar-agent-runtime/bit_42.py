"""Alternating bits test: true for 1010... patterns.

XOR with a right shift turns alternation into all-ones, which the n&(n+1) test recognizes.

What this IS: the 1010-pattern validator.
What this IS NOT: a palindrome test; direction matters not at all.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_42_VERSION = "bit-alternate-bits.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-alternate-bits.v1"


class BitError(Exception):
    """Fail-closed."""


def has_alternate_bits(n: int) -> bool:
    """True when binary has alternating 0/1 (e.g. 1010)."""
    if n < 0:
        raise BitError("non-negative only")
    x = n ^ (n >> 1)
    return (x & (x + 1)) == 0

def test_alt_true():
    assert has_alternate_bits(0b1010) is True
    assert has_alternate_bits(0b101) is True


def test_alt_false():
    assert has_alternate_bits(0b1011) is False


def test_alt_one():
    assert has_alternate_bits(1) is True

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
    test_alt_true()
    test_alt_false()
    test_alt_one()
    assert stdlib_only()
    print("bit-42 OK: alternate-bits")


if __name__ == "__main__":
    main()
