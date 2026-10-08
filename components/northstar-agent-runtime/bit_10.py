"""Hamming distance: count differing bits between two words.

XOR marks every differing position with a 1; popcount of the result is the distance.

What this IS: the metric behind fuzzy matching and error codes.
What this IS NOT: an edit distance; it counts bit flips only.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_10_VERSION = "bit-hamming-distance.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-hamming-distance.v1"


class BitError(Exception):
    """Fail-closed."""


def hamming_distance(x: int, y: int) -> int:
    """Count bit positions where x and y differ."""
    if x < 0 or y < 0:
        raise BitError("non-negative only")
    d = x ^ y
    count = 0
    while d:
        d &= d - 1
        count += 1
    return count

def test_hd_basic():
    assert hamming_distance(1, 4) == 2


def test_hd_one():
    assert hamming_distance(3, 1) == 1


def test_hd_zero():
    assert hamming_distance(0, 0) == 0


def test_hd_negative_raises():
    try:
        hamming_distance(-1, 2)
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
    test_hd_basic()
    test_hd_one()
    test_hd_zero()
    test_hd_negative_raises()
    assert stdlib_only()
    print("bit-10 OK: hamming-distance")


if __name__ == "__main__":
    main()
