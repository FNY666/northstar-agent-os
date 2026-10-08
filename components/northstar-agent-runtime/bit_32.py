"""Branchless max (32-bit): maximum without comparisons.

Same sign-broadcast blend as min, but keeps the larger operand instead.

What this IS: the constant-time max used to avoid branch mispredicts.
What this IS NOT: a generic max; inputs are pinned to 32-bit.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_32_VERSION = "bit-max-branchless32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-max-branchless32.v1"


class BitError(Exception):
    """Fail-closed."""


def _check32(v: int) -> None:
    if not -(2 ** 31) <= v < 2 ** 31:
        raise BitError("32-bit range required")


def max_branchless32(a: int, b: int) -> int:
    """max() without branching (32-bit)."""
    _check32(a)
    _check32(b)
    diff = a - b
    mask = diff >> 31
    return a - (diff & mask)

def test_max_second():
    assert max_branchless32(3, 7) == 7


def test_max_first():
    assert max_branchless32(7, 3) == 7


def test_max_equal():
    assert max_branchless32(5, 5) == 5


def test_max_negative():
    assert max_branchless32(-4, 2) == 2

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
    test_max_second()
    test_max_first()
    test_max_equal()
    test_max_negative()
    assert stdlib_only()
    print("bit-32 OK: max-branchless32")


if __name__ == "__main__":
    main()
