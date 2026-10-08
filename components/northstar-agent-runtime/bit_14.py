"""Clear bit: force bit i of n to 0.

AND with the complement of a single 1 at position i; only that bit can change.

What this IS: the flag-clearing primitive.
What this IS NOT: a shift; bit positions are preserved.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_14_VERSION = "bit-clear-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-clear-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def clear_bit(n: int, i: int) -> int:
    """Return n with bit i cleared to 0."""
    if n < 0 or i < 0:
        raise BitError("bad args")
    return n & ~(1 << i)

def test_clear_mid():
    assert clear_bit(0b1111, 2) == 0b1011


def test_clear_low():
    assert clear_bit(0b1000, 0) == 0b1000


def test_clear_idempotent():
    assert clear_bit(0b1010, 0) == 0b1010

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
    test_clear_mid()
    test_clear_low()
    test_clear_idempotent()
    assert stdlib_only()
    print("bit-14 OK: clear-bit")


if __name__ == "__main__":
    main()
