"""Branchless min (32-bit): minimum without comparisons.

The sign of (a - b), broadcast by arithmetic shift, selects which operand survives the blend.

What this IS: the constant-time min used to avoid branch mispredicts.
What this IS NOT: a generic min; inputs are pinned to 32-bit.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_31_VERSION = "bit-min-branchless32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-min-branchless32.v1"


class BitError(Exception):
    """Fail-closed."""


def _check32(v: int) -> None:
    if not -(2 ** 31) <= v < 2 ** 31:
        raise BitError("32-bit range required")


def min_branchless32(a: int, b: int) -> int:
    """min() without branching (32-bit)."""
    _check32(a)
    _check32(b)
    diff = a - b
    mask = diff >> 31
    return b + (diff & mask)

def test_min_first():
    assert min_branchless32(3, 7) == 3


def test_min_second():
    assert min_branchless32(7, 3) == 3


def test_min_equal():
    assert min_branchless32(5, 5) == 5


def test_min_negative():
    assert min_branchless32(-4, 2) == -4

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
    test_min_first()
    test_min_second()
    test_min_equal()
    test_min_negative()
    assert stdlib_only()
    print("bit-31 OK: min-branchless32")


if __name__ == "__main__":
    main()
