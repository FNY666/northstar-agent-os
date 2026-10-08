"""Range bitwise AND: AND of [left, right] via common prefix.

Shifting both bounds right until equal finds the common prefix; shifting back restores it.

What this IS: the O(log n) range-AND without iterating the range.
What this IS NOT: a loop over the interval; large ranges stay cheap.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_45_VERSION = "bit-range-bitwise-and.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-range-bitwise-and.v1"


class BitError(Exception):
    """Fail-closed."""


def range_bitwise_and(left: int, right: int) -> int:
    """AND of all numbers in [left, right] via common prefix."""
    if left < 0 or right < left:
        raise BitError("bad range")
    shift = 0
    while left < right:
        left >>= 1
        right >>= 1
        shift += 1
    return left << shift

def test_range_basic():
    assert range_bitwise_and(5, 7) == 4


def test_range_zero():
    assert range_bitwise_and(0, 0) == 0
    assert range_bitwise_and(0, 1) == 0


def test_range_wide():
    assert range_bitwise_and(12, 15) == 12


def test_range_bad_raises():
    try:
        range_bitwise_and(7, 5)
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
    test_range_basic()
    test_range_zero()
    test_range_wide()
    test_range_bad_raises()
    assert stdlib_only()
    print("bit-45 OK: range-bitwise-and")


if __name__ == "__main__":
    main()
