"""Set bit: force bit i of n to 1.

OR with a single 1 at position i; all other bits pass through unchanged.

What this IS: the flag-setting primitive.
What this IS NOT: a toggle; it never clears.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_13_VERSION = "bit-set-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-set-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def set_bit(n: int, i: int) -> int:
    """Return n with bit i set to 1."""
    if n < 0 or i < 0:
        raise BitError("bad args")
    return n | (1 << i)

def test_set_low():
    assert set_bit(0b1000, 0) == 0b1001


def test_set_from_zero():
    assert set_bit(0, 5) == 32


def test_set_idempotent():
    assert set_bit(0b1010, 1) == 0b1010

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
    test_set_low()
    test_set_from_zero()
    test_set_idempotent()
    assert stdlib_only()
    print("bit-13 OK: set-bit")


if __name__ == "__main__":
    main()
