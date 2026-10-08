"""Single number: find the element that appears once via XOR.

XOR is its own inverse and commutes, so pairs cancel and the lone element remains.

What this IS: the classic linear-time, O(1)-space single-number finder.
What this IS NOT: a frequency map; it cannot report counts.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_03_VERSION = "bit-single-number.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-single-number.v1"


class BitError(Exception):
    """Fail-closed."""


def single_number(nums: list) -> int:
    """Every element appears twice except one; return it via XOR."""
    if not nums:
        raise BitError("empty input")
    x = 0
    for v in nums:
        x ^= v
    return x

def test_single_basic():
    assert single_number([2, 2, 1]) == 1


def test_single_middle():
    assert single_number([4, 1, 2, 1, 2]) == 4


def test_single_alone():
    assert single_number([1]) == 1


def test_single_empty_raises():
    try:
        single_number([])
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
    test_single_basic()
    test_single_middle()
    test_single_alone()
    test_single_empty_raises()
    assert stdlib_only()
    print("bit-03 OK: single-number")


if __name__ == "__main__":
    main()
