"""Single number II: lone element among triples via bit state machine.

Two bitmasks track how many times each bit position has been seen modulo 3.

What this IS: the O(n)/O(1) solution for the appears-three-times variant.
What this IS NOT: a counter map; it keeps only two machine words.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_24_VERSION = "bit-single-number-ii.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-single-number-ii.v1"


class BitError(Exception):
    """Fail-closed."""


def single_number_ii(nums: list) -> int:
    """Every element appears 3x except one; bit-state machine."""
    if not nums:
        raise BitError("empty input")
    ones = twos = 0
    for x in nums:
        ones = (ones ^ x) & ~twos
        twos = (twos ^ x) & ~ones
    return ones

def test_ii_basic():
    assert single_number_ii([2, 2, 3, 2]) == 3


def test_ii_large():
    assert single_number_ii([0, 1, 0, 1, 0, 1, 99]) == 99


def test_ii_negative():
    assert single_number_ii([-2, -2, -2, 5]) == 5


def test_ii_empty_raises():
    try:
        single_number_ii([])
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
    test_ii_basic()
    test_ii_large()
    test_ii_negative()
    test_ii_empty_raises()
    assert stdlib_only()
    print("bit-24 OK: single-number-ii")


if __name__ == "__main__":
    main()
