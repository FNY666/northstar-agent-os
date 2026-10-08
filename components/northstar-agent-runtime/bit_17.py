"""Smear rightmost 1: turn trailing zeros into ones with n | (n-1).

n - 1 flips the trailing zeros to one and borrows the lowest 1; OR merges both shapes.

What this IS: the range-fill step used before prefix masks.
What this IS NOT: a shift; the lowest 1-bit stays where it is.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_17_VERSION = "bit-smear-rightmost-one.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-smear-rightmost-one.v1"


class BitError(Exception):
    """Fail-closed."""


def smear_rightmost_one(n: int) -> int:
    """n | (n-1): turn trailing zeros into ones."""
    if n <= 0:
        raise BitError("n > 0 required")
    return n | (n - 1)

def test_smear_basic():
    assert smear_rightmost_one(12) == 15  # 1100 -> 1111


def test_smear_pow2():
    assert smear_rightmost_one(8) == 15


def test_smear_noop():
    assert smear_rightmost_one(7) == 7


def test_smear_zero_raises():
    try:
        smear_rightmost_one(0)
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
    test_smear_basic()
    test_smear_pow2()
    test_smear_noop()
    test_smear_zero_raises()
    assert stdlib_only()
    print("bit-17 OK: smear-rightmost-one")


if __name__ == "__main__":
    main()
