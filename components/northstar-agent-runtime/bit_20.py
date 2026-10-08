"""Swap two bits: exchange bit positions i and j.

When the two bits differ, XOR with both masks flips each of them exactly once.

What this IS: the minimal conditional bit permutation.
What this IS NOT: a rotate; only the two named positions move.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_20_VERSION = "bit-swap-bits.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-swap-bits.v1"


class BitError(Exception):
    """Fail-closed."""


def swap_bits(n: int, i: int, j: int) -> int:
    """Swap bit positions i and j."""
    if n < 0 or i < 0 or j < 0:
        raise BitError("bad args")
    if ((n >> i) & 1) != ((n >> j) & 1):
        n ^= (1 << i) | (1 << j)
    return n

def test_swap_diff():
    assert swap_bits(0b10, 0, 1) == 0b01


def test_swap_same():
    assert swap_bits(0b101, 0, 2) == 0b101


def test_swap_high_low():
    assert swap_bits(8, 0, 3) == 1

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
    test_swap_diff()
    test_swap_same()
    test_swap_high_low()
    assert stdlib_only()
    print("bit-20 OK: swap-bits")


if __name__ == "__main__":
    main()
