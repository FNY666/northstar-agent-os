"""Clear lowest set bit: n & (n - 1) drops the rightmost 1.

Subtracting one borrows through the lowest 1-bit, so AND clears exactly that bit.

What this IS: the iteration step behind Kernighan popcount.
What this IS NOT: a shift; higher bits are untouched.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_09_VERSION = "bit-clear-lowest-set-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-clear-lowest-set-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def clear_lowest_set_bit(n: int) -> int:
    """n & (n-1): clear the lowest set bit."""
    return n & (n - 1)

def test_clear_basic():
    assert clear_lowest_set_bit(12) == 8


def test_clear_odd():
    assert clear_lowest_set_bit(7) == 6


def test_clear_pow2():
    assert clear_lowest_set_bit(8) == 0

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
    test_clear_basic()
    test_clear_odd()
    test_clear_pow2()
    assert stdlib_only()
    print("bit-09 OK: clear-lowest-set-bit")


if __name__ == "__main__":
    main()
